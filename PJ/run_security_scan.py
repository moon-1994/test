import os
import argparse
from src.terraform_analyzer.terraform_scanner import TerraformScanner
from src.notification.notification_manager import NotificationManager

def main():
    """메인 함수"""
    # 명령줄 인자 파싱
    parser = argparse.ArgumentParser(description='Terraform 코드 보안 검사 실행')
    parser.add_argument('--dir', '-d', help='검사할 Terraform 디렉토리 경로', default='./examples')
    parser.add_argument('--output', '-o', help='결과 저장 디렉토리', default='./scan_results')
    parser.add_argument('--mock', '-m', help='모의 스캔 사용 (도구 설치 없이 테스트)', action='store_true')
    parser.add_argument('--block', '-b', help='심각한 취약점 발견 시 배포 차단', action='store_true')
    parser.add_argument('--email', '-e', help='이메일 알림 활성화', action='store_true')
    parser.add_argument('--sns', '-s', help='SNS 알림 활성화', action='store_true')
    
    args = parser.parse_args()
    
    # 알림 설정
    notification_config = {
        'email': {
            'enabled': args.email,
            'smtp_server': os.environ.get('SMTP_SERVER', 'smtp.gmail.com'),
            'smtp_port': int(os.environ.get('SMTP_PORT', '587')),
            'sender_email': os.environ.get('SENDER_EMAIL', ''),
            'sender_password': os.environ.get('SENDER_PASSWORD', ''),
            'recipients': [email.strip() for email in os.environ.get('EMAIL_RECIPIENTS', '').split(',') if email.strip()]
        },
        'sns': {
            'enabled': args.sns,
            'topic_arn': os.environ.get('SNS_TOPIC_ARN', ''),
            'region': os.environ.get('AWS_REGION', 'us-east-1')
        },
        'console': {
            'enabled': True
        }
    }
    
    # 스캐너 생성 및 실행
    scanner = TerraformScanner(
        terraform_dir=args.dir,
        output_dir=args.output,
        notification_config=notification_config
    )
    
    print(f"Terraform 보안 스캔 시작 - 디렉토리: {args.dir}")
    results = scanner.run_all_scans(use_mock=args.mock)
    
    # 결과 요약 출력
    critical_findings = results.get('critical_findings', [])
    
    print("\n=== 보안 검사 결과 요약 ===")
    print(f"총 취약점 수: {sum(len(tool_results.get('results', [])) for tool_results in results.get('scan_tools', {}).values())}")
    print(f"심각한 취약점 수: {len(critical_findings)}")
    
    # NIST 등급 정보 출력 (있는 경우)
    if 'nist_graded' in results:
        nist_results = results['nist_graded'].get('summary', {})
        print(f"\n=== NIST 800-53 등급화 결과 ===")
        print(f"위험 등급: {nist_results.get('risk_level', 'UNKNOWN')}")
        print(f"위험 점수: {nist_results.get('overall_risk_score', 0)}/100")
        
        # NIST 통제 항목별 위반 수
        nist_controls = nist_results.get('nist_controls', {})
        if nist_controls:
            print("\nNIST 800-53 통제 항목별 위반:")
            for control, info in nist_controls.items():
                print(f"- {control} ({info.get('description', '')}): {info.get('count', 0)}개")
    
    # 배포 차단 정보 출력
    if results.get('should_block_deployment', False):
        print("\n⛔ 배포가 차단되었습니다!")
        if args.block:
            print("--block 옵션이 활성화되어 있어 CI/CD 파이프라인이 중단됩니다.")
            exit(1)
        else:
            print("--block 옵션이 비활성화되어 있어 경고만 표시합니다.")
    
    print("\n테스트 완료.")

if __name__ == "__main__":
    main()