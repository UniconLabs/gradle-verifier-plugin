import groovy.util.logging.Slf4j
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRingCollection
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project

class PGPVerifyPluginExtension {
    File pgpKeyRing
}

@Slf4j
class PGPVerifyPlugin implements Plugin<Project> {
    void apply(Project project) {
        project.extensions.create("PGPVerifyPlugin", PGPVerifyPluginExtension)

        project.configurations {
            verification
        }

        project.afterEvaluate {
            println "Verifying file signatures"
            def publicKeyRing  = new BcPGPPublicKeyRingCollection(project.PGPVerifyPlugin.pgpKeyRing.newInputStream())

            project.configurations.compile.allDependencies.each {dep ->
                project.dependencies {
                    verification "${dep.group}:${dep.name}:${dep.version}@jar.asc"
                }
            }

            project.configurations.compile.resolvedConfiguration.resolvedArtifacts.each { artifact ->
                def sig = project.configurations.verification.find { file -> file.name == artifact.file.name + ".asc" }

                def pgpSignature = PGPUtil.getDecoderStream(sig.newInputStream()).with {
                    new PGPObjectFactory(it, new BcKeyFingerprintCalculator()).nextObject().get(0)
                }

                def publicKey = publicKeyRing.getPublicKey(pgpSignature.getKeyID())

                pgpSignature.init(new BcPGPContentVerifierBuilderProvider(), publicKey)

                artifact.file.withInputStream {
                    def t
                    while ((t = it.read()) >= 0) {
                        pgpSignature.update((byte) t)
                    }
                }
                if (!pgpSignature.verify()) {
                    throw new GradleException("signature for file did not verify: ${artifact.file}")
                }
            }
        }
    }
}