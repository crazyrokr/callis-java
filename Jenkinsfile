// T63: declarative pipeline for the reachability gate.
//
// Stages: Build & SBOM -> OSV cache -> Reachability Analysis, then
// archive the reports. The pipeline fails naturally on analyzer exit 1
// (reachable vulnerability) — no special handling needed.
//
// Requirements: JDK 25 on the agent (A12) and Maven on PATH; the
// analyzer builds with the committed ./gradlew wrapper, no Gradle
// installation required (a 'withGradle' tool is an alternative).
//
// The committed examples/vulnerable-demo pins log4j 2.14.1, so this
// pipeline fails by design until the demo's log4j.version is switched
// to the fixed release 2.25.5.

pipeline {
    agent any

    environment {
        OSV_DIR = 'osv-maven'
        ANALYZER_JAR = 'build/libs/reachability-analyzer-0.1.0-SNAPSHOT-all.jar'
        TARGET_DIR = 'examples/vulnerable-demo'
    }

    stages {
        stage('Build & SBOM') {
            steps {
                // Target project (Maven variant; the Gradle variant is
                // documented in .github/workflows/reachability-check.yml).
                dir("${TARGET_DIR}") {
                    sh 'mvn -B package'
                    sh 'mvn -B dependency:build-classpath -Dmdep.outputFile=target/cp.txt'
                }
                sh './gradlew shadowJar'
            }
        }

        stage('OSV cache') {
            steps {
                // Cache the snapshot across builds (A14 pinning): reuse the
                // agent's copy when present, otherwise download. With the
                // Pipeline Cache plugin, replace the guard with:
                //   cache('osv-maven', key: "${OSV_DIR}-\${sha256}")
                if (fileExists("${OSV_DIR}.sha256")) {
                    // Shell substitution in a plain string: named-argument
                    // calls inside Groovy $(...) interpolation do not parse.
                    sh "echo \"OSV snapshot cache hit: \$(cut -d' ' -f1 ${OSV_DIR}.sha256)\""
                } else {
                    sh "bash scripts/download-osv.sh ${OSV_DIR}"
                }
                // Share across concurrent builds on the same agent.
                stash name: "${OSV_DIR}", includes: "${OSV_DIR}/**,${OSV_DIR}.sha256"
            }
        }

        stage('Reachability Analysis') {
            steps {
                // Exit 1 (reachable) fails the pipeline naturally; exit 2/3
                // (usage/analysis failure) fail it just as hard — a gate
                // must never pass on a broken run.
                sh """
                    java -jar ${ANALYZER_JAR} \
                      --app-classes=${TARGET_DIR}/target/classes \
                      --classpath-file=${TARGET_DIR}/target/cp.txt \
                      --sbom=${TARGET_DIR}/target/bom.json \
                      --osv-dir=${OSV_DIR} \
                      --osv-checksum="\$(cut -d' ' -f1 ${OSV_DIR}.sha256)" \
                      --format=json,junitxml \
                      --output=reachability-report
                """
            }
        }
    }

    post {
        always {
            // The reports are the evidence — archive them on every outcome.
            archiveArtifacts artifacts: 'reachability-report.*', allowEmptyArchive: true
            archiveArtifacts artifacts: "${TARGET_DIR}/target/bom.json", allowEmptyArchive: true
        }
        failure {
            echo 'Reachable vulnerability found — see reachability-report.junit.xml'
        }
    }
}
