import json
import boto3
import re
import os
from datetime import datetime

def lambda_handler(event, context):
    """취약점 자동 마스킹 Lambda 함수"""
    
    print("보안 취약점 자동 마스킹 함수 시작")
    
    # 이벤트에서 필요한 정보 추출
    bucket_name = event.get('bucket_name')
    key = event.get('key')
    critical_findings = event.get('critical_findings', [])
    
    if not bucket_name or not key:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'bucket_name과 key는 필수 파라미터입니다.'})
        }
    
    # 결과 초기화
    results = {
        'masked_vulnerabilities': [],
        'failed_maskings': [],
        'original_file': key,
        'modified_file': key.replace('.tf', '_masked.tf')
    }
    
    try:
        # S3에서 파일 가져오기
        s3_client = boto3.client('s3')
        response = s3_client.get_object(Bucket=bucket_name, Key=key)
        file_content = response['Body'].read().decode('utf-8')
        
        # 변경된 내용을 저장할 변수
        modified_content = file_content
        
        # 각 심각한 취약점에 대해 마스킹 시도
        for finding in critical_findings:
            try:
                rule_id = finding.get('rule_id', '')
                resource = finding.get('resource', '')
                line_start = finding.get('line_start', 0)
                
                # 마스킹 적용
                result, modified_content = apply_masking(modified_content, rule_id, resource, line_start)
                
                if result:
                    results['masked_vulnerabilities'].append({
                        'rule_id': rule_id,
                        'resource': resource,
                        'line': line_start,
                        'status': 'success'
                    })
                else:
                    results['failed_maskings'].append({
                        'rule_id': rule_id,
                        'resource': resource,
                        'line': line_start,
                        'reason': 'No matching pattern found'
                    })
            
            except Exception as e:
                results['failed_maskings'].append({
                    'rule_id': finding.get('rule_id', ''),
                    'resource': finding.get('resource', ''),
                    'line': finding.get('line_start', 0),
                    'reason': str(e)
                })
        
        # 변경된 파일 S3에 업로드
        if modified_content != file_content:
            masked_key = key.replace('.tf', '_masked.tf')
            s3_client.put_object(
                Bucket=bucket_name,
                Key=masked_key,
                Body=modified_content.encode('utf-8'),
                ContentType='text/plain'
            )
            
            # 원본 파일도 백업
            backup_key = f"{key}.{datetime.now().strftime('%Y%m%d%H%M%S')}.bak"
            s3_client.copy_object(
                Bucket=bucket_name,
                CopySource={'Bucket': bucket_name, 'Key': key},
                Key=backup_key
            )
            
            # 결과 업데이트
            results['modified_file'] = masked_key
            results['backup_file'] = backup_key
        
        # 요약 정보 추가
        results['summary'] = {
            'total_findings': len(critical_findings),
            'masked_count': len(results['masked_vulnerabilities']),
            'failed_count': len(results['failed_maskings'])
        }
        
        # SNS 알림 전송 (설정된 경우)
        sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        if sns_topic_arn:
            send_notification(sns_topic_arn, results)
        
        return {
            'statusCode': 200,
            'body': json.dumps(results)
        }
    
    except Exception as e:
        print(f"오류 발생: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def apply_masking(content, rule_id, resource, line_start):
    """취약점 유형별 마스킹 적용"""
    # 파일 내용을 줄 단위로 분할
    lines = content.split('\n')
    
    # 리소스 블록 찾기
    resource_pattern = re.compile(rf'resource\s+["\'](\w+)["\']\s+["\']({resource.split(".")[-1]})["\']\s*{{')
    resource_start_line = -1
    resource_end_line = -1
    
    for i, line in enumerate(lines):
        if resource_pattern.search(line):
            resource_start_line = i
            # 리소스 블록의 끝 찾기
            brace_count = 0
            for j in range(i, len(lines)):
                if '{' in lines[j]:
                    brace_count += lines[j].count('{')
                if '}' in lines[j]:
                    brace_count -= lines[j].count('}')
                if brace_count == 0:
                    resource_end_line = j
                    break
            break
    
    if resource_start_line == -1 or resource_end_line == -1:
        return False, content
    
    # 마스킹 적용
    modified = False
    
    # 취약점 유형별 마스킹 로직
    # S3 공개 액세스 관련 취약점
    if rule_id in ['aws-s3-no-public-access-with-acl', 'CKV_AWS_20', 'AC_AWS_0207']:
        for i in range(resource_start_line, resource_end_line + 1):
            if re.search(r'acl\s*=\s*["\'](public-read|public-read-write)["\']', lines[i]):
                lines[i] = re.sub(
                    r'(acl\s*=\s*["\'])(public-read|public-read-write)(["\'])',
                    r'\1private\3  # AUTO-MASKED: 보안 취약점 수정됨 (원래 값: \2)',
                    lines[i]
                )
                modified = True
                break
    
    # S3 암호화 관련 취약점
    elif rule_id in ['aws-s3-enable-bucket-encryption', 'CKV_AWS_24']:
        # 암호화 설정이 없는지 확인
        has_encryption = False
        for i in range(resource_start_line, resource_end_line + 1):
            if 'server_side_encryption_configuration' in lines[i]:
                has_encryption = True
                break
        
        if not has_encryption:
            # 암호화 설정 추가
            encryption_config = [
                '  # AUTO-ADDED: 보안 취약점 수정 - 서버 측 암호화 활성화',
                '  server_side_encryption_configuration {',
                '    rule {',
                '      apply_server_side_encryption_by_default {',
                '        sse_algorithm = "AES256"',
                '      }',
                '    }',
                '  }'
            ]
            
            # 리소스 블록 닫는 괄호 바로 앞에 삽입
            lines = lines[:resource_end_line] + encryption_config + lines[resource_end_line:]
            modified = True
    
    # EC2 IMDSv2 관련 취약점
    elif rule_id in ['aws-ec2-enforce-http-token-imds', 'CKV_AWS_79']:
        # 메타데이터 옵션이 없는지 확인
        has_metadata_options = False
        for i in range(resource_start_line, resource_end_line + 1):
            if 'metadata_options' in lines[i]:
                has_metadata_options = True
                break
        
        if not has_metadata_options:
            # 메타데이터 옵션 추가
            metadata_options = [
                '  # AUTO-ADDED: 보안 취약점 수정 - IMDSv2 강제',
                '  metadata_options {',
                '    http_endpoint = "enabled"',
                '    http_tokens   = "required"',
                '  }'
            ]
            
            # 리소스 블록 닫는 괄호 바로 앞에 삽입
            lines = lines[:resource_end_line] + metadata_options + lines[resource_end_line:]
            modified = True
    
    # IAM 과도한 권한 관련 취약점
    elif rule_id in ['aws-iam-no-policy-wildcards', 'CKV_AWS_63', 'AC_AWS_0014']:
        for i in range(resource_start_line, resource_end_line + 1):
            if re.search(r'(Action|action)\s*=\s*["\']\*["\']', lines[i]):
                lines[i] = re.sub(
                    r'(Action|action)\s*=\s*["\']\*["\']',
                    r'\1 = ["s3:GetObject", "s3:ListBucket"]  # AUTO-MASKED: 와일드카드 권한 제한됨',
                    lines[i]
                )
                modified = True
                break
    
    # 변경사항이 있으면 수정된 내용 반환
    if modified:
        return True, '\n'.join(lines)
    
    return False, content

def send_notification(topic_arn, results):
    """SNS를 통한 알림 전송"""
    try:
        sns_client = boto3.client('sns')
        
        masked_count = results['summary']['masked_count']
        failed_count = results['summary']['failed_count']
        
        subject = f"보안 취약점 자동 마스킹 완료: {masked_count}개 수정됨"
        
        message = f"보안 취약점 자동 마스킹 결과:\n\n"
        message += f"- 처리된 파일: {results['original_file']}\n"
        message += f"- 마스킹된 파일: {results['modified_file']}\n"
        message += f"- 성공적으로 마스킹된 취약점: {masked_count}개\n"
        message += f"- 마스킹 실패한 취약점: {failed_count}개\n\n"
        
        if masked_count > 0:
            message += "마스킹된 취약점:\n"
            for i, vuln in enumerate(results['masked_vulnerabilities'], 1):
                message += f"{i}. 규칙: {vuln['rule_id']}, 리소스: {vuln['resource']}\n"
            
            message += "\n"
        
        if failed_count > 0:
            message += "마스킹 실패한 취약점:\n"
            for i, vuln in enumerate(results['failed_maskings'], 1):
                message += f"{i}. 규칙: {vuln['rule_id']}, 리소스: {vuln['resource']}, 이유: {vuln['reason']}\n"
        
        # SNS 메시지 발행
        sns_client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message
        )
        
        print(f"알림이 SNS 주제 {topic_arn}로 전송되었습니다.")
        
    except Exception as e:
        print(f"알림 전송 중 오류 발생: {e}")