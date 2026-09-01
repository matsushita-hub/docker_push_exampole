pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                // GitHubからコードを取得
                checkout scm
            }
        }
        
        stage('Install Dependencies') {
            steps {
                echo '依存パッケージをインストールしています...'
                sh 'npm ci'
            }
        }
        
        stage('Lint & Test') {
            steps {
                echo '構文チェックとテストを実行しています...'
                // エラーがあればここでビルドが停止します
                // sh 'npm run lint'
                // sh 'npm test'
            }
        }
        
        stage('Package Artifact') {
            steps {
                echo 'SFCCデプロイ用のZipアーカイブを作成しています...'
                // 例: cartridgesディレクトリを archive.zip に圧縮
                sh 'zip -r archive.zip cartridges/'
            }
        }
        
        stage('Simulate Deploy') {
            steps {
                echo '【モック】SFCC環境へのデプロイをシミュレーションします'
                // 実際の sfcc-ci コマンドの代わりに実行予定のコマンドを出力して確認
                sh 'echo "Running: sfcc-ci code:deploy archive.zip -i sandbox.demandware.net"'
            }
        }
    }
    
    post {
        success {
            echo 'パイプラインが正常に完了しました。'
            // 作成したZipファイルをJenkinsのUIからダウンロードできるように保存
            archiveArtifacts artifacts: 'archive.zip', fingerprint: true
        }
        failure {
            echo 'パイプラインが失敗しました。ログを確認してください。'
        }
    }
}
