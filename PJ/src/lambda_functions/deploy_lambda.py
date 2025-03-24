import boto3
import zipfile
import os
import io
import time

def deploy_lambda():
    """Lambda 함수 배포"""
    # Lambda 함수 설정
    function_name = 'terraform_security_auto_masking'
    lambda_role_arn = os.environ.get('LAMBDA_ROLE_ARN')
    sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
    
    if not lambda_role_arn:
        print("LAMBDA_ROLE_ARN 환경 변수가 설정되지 않았습니다.")
        print("Lambda 실행 역할 ARN을 설정하세요.")
        return False
    
    # 소스 파일 경로
    src_file = os.path.join(os.path.dirname(__file__), 'auto_masking_lambda.py')
    
    # Lambda 함수 패키징
    print(f"Lambda 함수 {function_name} 패키징 중...")
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.write(src_file, os.path.basename(src_file))
    
    zip_buffer.seek(0)
    zip_data = zip_buffer.read()
    
    # Lambda 클라이언트 생성
    lambda_client = boto3.client('lambda')
    
    try:
        # 기존 Lambda 함수 확인
        try:
            lambda_client.get_function(FunctionName=function_name)
            function_exists = True
            print(f"기존 Lambda 함수 {function_name}을 업데이트합니다.")
        except lambda_client.exceptions.ResourceNotFoundException:
            function_exists = False
            print(f"새 Lambda 함수 {function_name}을 생성합니다.")
        
        # Lambda 함수 생성 또는 업데이트
        if function_exists:
            # 기존 함수 업데이트
            response = lambda_client.update_function_code(
                FunctionName=function_name,
                ZipFile=zip_data,
                Publish=True
            )
            
            # 환경 변수 업데이트
            if sns_topic_arn:
                lambda_client.update_function_configuration(
                    FunctionName=function_name,
                    Environment={
                        'Variables': {
                            'SNS_TOPIC_ARN': sns_topic_arn
                        }
                    }
                )
        else:
            # 새 함수 생성
            response = lambda_client.create_function(
                FunctionName=function_name,
                Runtime='python3.9',
                Role=lambda_role_arn,
                Handler='auto_masking_lambda.lambda_handler',
                Code={
                    'ZipFile': zip_data
                },
                Description='Terraform 보안 취약점 자동 마스킹 함수',
                Timeout=30,
                MemorySize=128,
                Publish=True,
                Environment={
                    'Variables': {
                        'SNS_TOPIC_ARN': sns_topic_arn or ''
                    }
                }
            )
        
        # S3 이벤트 트리거 설정은 AWS 콘솔 또는 별도 스크립트로 구성 가능
        
        print(f"Lambda 함수 배포 완료: {response.get('FunctionArn')}")
        return True
    
    except Exception as e:
        print(f"Lambda 함수 배포 중 오류 발생: {e}")
        return False

if __name__ == "__main__":
    deploy_lambda()