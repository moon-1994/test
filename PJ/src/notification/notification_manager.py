import smtplib
import json
import os
import boto3
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

class NotificationManager:
    """보안 알림 관리자"""
    
    def __init__(self, config=None):
        """알림 관리자 초기화"""
        self.config = config or {}
        
        # 기본 설정
        self.default_config = {
            'email': {
                'enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'sender_email': '',
                'sender_password': '',
                'recipients': []
            },
            'sns': {
                'enabled': False,
                'topic_arn': '',
                'region': 'us-east-1'
            },
            'console': {
                'enabled': True
            }
        }
        
        # 설정 병합
        self.config = {**self.default_config, **self.config}
    
    def send_alert(self, subject, message, findings=None, block_deployment=False):
        """알림 전송"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = self._format_message(timestamp, subject, message, findings, block_deployment)
        
        success = True
        
        # 콘솔 알림
        if self.config['console']['enabled']:
            self._send_console_alert(timestamp, subject, message, findings, block_deployment)
        
        # 이메일 알림
        if self.config['email']['enabled']:
            email_success = self._send_email_alert(subject, formatted_message)
            success = success and email_success
        
        # SNS 알림
        if self.config['sns']['enabled']:
            sns_success = self._send_sns_alert(subject, formatted_message)
            success = success and sns_success
        
        return success
    
    def _format_message(self, timestamp, subject, message, findings=None, block_deployment=False):
        """알림 메시지 포맷팅"""
        formatted_message = f"[{timestamp}] {subject}\n\n{message}\n"
        
        if block_deployment:
            formatted_message += "\n⛔ 배포가 차단되었습니다!\n"
        
        if findings:
            formatted_message += "\n심각한 취약점 목록:\n"
            for i, finding in enumerate(findings, 1):
                severity = finding.get('severity', '')
                description = finding.get('description', '')
                file = finding.get('file', '')
                line = finding.get('line_start', '')
                resource = finding.get('resource', '')
                rule_id = finding.get('rule_id', '')
                
                formatted_message += f"{i}. [{severity}] {description}\n"
                formatted_message += f"   파일: {file}, 라인: {line}\n"
                formatted_message += f"   리소스: {resource}\n"
                formatted_message += f"   규칙: {rule_id}\n\n"
        
        return formatted_message
    
    def _send_console_alert(self, timestamp, subject, message, findings=None, block_deployment=False):
        """콘솔 알림 출력"""
        print("\n" + "="*60)
        print(f"보안 알림: {subject}")
        print(f"시간: {timestamp}")
        print("-"*60)
        print(message)
        
        if block_deployment:
            print("\n⛔ 배포가 차단되었습니다!")
        
        if findings:
            print("\n심각한 취약점 목록:")
            for i, finding in enumerate(findings, 1):
                severity = finding.get('severity', '')
                description = finding.get('description', '')
                file = finding.get('file', '')
                line = finding.get('line_start', '')
                resource = finding.get('resource', '')
                
                print(f"  {i}. [{severity}] {description}")
                print(f"     파일: {file}, 라인: {line}")
                print(f"     리소스: {resource}")
                print()
        
        print("="*60 + "\n")
        return True
    
    def _send_email_alert(self, subject, message):
        """이메일 알림 전송"""
        try:
            # 이메일 설정
            smtp_server = self.config['email']['smtp_server']
            smtp_port = self.config['email']['smtp_port']
            sender_email = self.config['email']['sender_email']
            sender_password = self.config['email']['sender_password']
            recipients = self.config['email']['recipients']
            
            if not sender_email or not sender_password or not recipients:
                print("이메일 설정이 완료되지 않았습니다.")
                return False
            
            # 이메일 메시지 생성
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = f"[보안 알림] {subject}"
            
            # 본문 추가
            msg.attach(MIMEText(message, 'plain'))
            
            # SMTP 서버 연결 및 이메일 전송
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.send_message(msg)
            
            print(f"이메일 알림이 {len(recipients)}명의 수신자에게 전송되었습니다.")
            return True
        
        except Exception as e:
            print(f"이메일 전송 중 오류 발생: {e}")
            return False
    
    def _send_sns_alert(self, subject, message):
        """AWS SNS 알림 전송"""
        try:
            # SNS 설정
            topic_arn = self.config['sns']['topic_arn']
            region = self.config['sns']['region']
            
            if not topic_arn:
                print("SNS 주제 ARN이 설정되지 않았습니다.")
                return False
            
            # SNS 클라이언트 생성
            sns_client = boto3.client('sns', region_name=region)
            
            # SNS 메시지 전송
            response = sns_client.publish(
                TopicArn=topic_arn,
                Message=message,
                Subject=f"[보안 알림] {subject[:80]}"  # SNS 제목은 최대 100자로 제한
            )
            
            print(f"SNS 알림이 전송되었습니다. MessageId: {response['MessageId']}")
            return True
        
        except Exception as e:
            print(f"SNS 알림 전송 중 오류 발생: {e}")
            return False