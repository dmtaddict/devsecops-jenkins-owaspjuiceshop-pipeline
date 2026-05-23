pipeline {
    agent any

    options {
        timeout(time: 30, unit: 'MINUTES')
        keepJenkinsSystemLog()
    }

    stages {
        stage('1. Checkout Code') {
            steps {
                echo 'Скачиваем из GitHub исходники и конфиги'
                checkout scm
            }
        }

        stage('2. SAST (Semgrep)') {
            steps {
                echo 'Cкачиваем OWASP Juice shop и проверяем его исходники с помощью Semgrep'
                sh 'git clone --depth 1 https://github.com/juice-shop/juice-shop.git vuln_app'
                sh '''
                    docker run --rm \
                    -v "${WORKSPACE}/vuln_app:/src" \
                    returntocorp/semgrep semgrep scan \
                    --config=p/security-audit \
                    --json -o "${WORKSPACE}/semgrep-report.json" || true
                '''
                echo 'Завершено сканирование исходников'
            }
        }
        
        stage('3. SCA (Trivy)') {
            steps {
                echo 'Запускаем анализ зависимостей с помощью Trivy'
                sh '''
                    docker run --rm \
                    -v "${WORKSPACE}/vuln_app:/apps" \
                    aquasec/trivy:latest fs \
                    --vuln-type library \
                    --format json \
                    -o "${WORKSPACE}/trivy-report.json" /apps || true
                '''
                echo 'Завершено сканирование зависимостей'
            }
        }
        
        stage('4. Deploy App') {
            steps {
                echo 'Запускаем Juice Shop'
                sh '''
                    docker run -d \
                    --name vuln-app \
                    --network owaspjuiceshop-pipeline \
                    -p 3000:3000 \
                    bkimminich/juice-shop:v16.0.0
                '''
                sh 'sleep 15'
                echo 'Запуск Juice Shop завершён'
            }
        }

        stage('5. DAST (OWASP ZAP)') {
            steps {
                echo 'Запускаем динамический анализ с помощью OWASP ZAP'
                sh '''
                    docker run --rm \
                    -v "${WORKSPACE}:/zap/wrk/:rw" \
                    --network owaspjuiceshop-pipeline \
                    -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
                    -t http://vuln-app:3000 \
                    -c zap_config.conf \
                    -r zap-report.html || true
                '''
                echo 'Динамическое сканирование завершено'
            }
        }
    }

    post {
        always {
            // Удаляем всё
            sh 'docker stop vuln-app && docker rm vuln-app || true'
            sh 'rm -rf vuln_app || true'
            
            echo 'Сохранение артефактов безопасности в Jenkins'
            archiveArtifacts artifacts: 'semgrep-report.json, trivy-report.json, zap-report.html', allowEmptyArchive: false
        }
    }
}
