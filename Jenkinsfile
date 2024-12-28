pipeline {
    agent any
    
    environment {
        VENV = "venv" // Virtual environment directory
        REQUIREMENTS = "requirements.txt"
    }
    
    stages {
        stage('Clone Repository') {
            steps {
                echo 'Cloning the repository...'
                git 'https://github.com/Mar-Kh0r/SSD-Final.git'
            }
        }
        
        stage('Install Dependencies') {
            steps {
                echo 'Setting up virtual environment and installing dependencies...'
                sh '''
                python3 -m venv ${VENV}
                source ${VENV}/bin/activate
                pip install -r ${REQUIREMENTS}
                '''
            }
        }
        
        stage('Run Unit Tests') {
            steps {
                echo 'Running unit tests...'
                sh '''
                source ${VENV}/bin/activate
                pytest --junitxml=reports/test-results.xml
                '''
            }
        }
        
        stage('Build Application') {
            steps {
                echo 'Building the application...'
                sh '''
                source ${VENV}/bin/activate
                python setup.py build
                '''
            }
        }
        
        stage('Deploy Application') {
            steps {
                echo 'Deploying the application...'
                sh '''
                source ${VENV}/bin/activate
                flask run --host=0.0.0.0 --port=8080
                '''
            }
        }
    }
    
    post {
        always {
            echo 'Pipeline finished.'
            cleanWs() // Clean workspace after build
        }
        success {
            echo 'Pipeline executed successfully!'
        }
        failure {
            echo 'Pipeline failed!'
        }
    }
}
