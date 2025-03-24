import subprocess
import json
import os
import yaml
from datetime import datetime
from src.notification.notification_manager import NotificationManager
# 절대 경로 임포트 사용
from src.terraform_analyzer.security_standards import SecurityStandards
from src.terraform_analyzer.nist_grader import NISTGrader

class TerraformScanner:
    def __init__(self, terraform_dir, output_dir=None, notification_config=None):
        """Terraform 코드 스캐너 초기화"""
        self.terraform_dir = terraform_dir
        self.output_dir = output_dir or os.path.join(os.getcwd(), 'scan_results')
        self.security_standards = SecurityStandards()
        self.notification_manager = NotificationManager(notification_config)
        
        # 결과 디렉토리 생성
        os.makedirs(self.output_dir, exist_ok=True)
    
    def run_tfsec(self):
        """tfsec 도구를 사용하여 Terraform 코드 스캔"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.output_dir, f'tfsec_results_{timestamp}.json')
        
        try:
            # tfsec 실행 (JSON 형식으로 결과 출력)
            cmd = f"tfsec {self.terraform_dir} --format json -o {output_file}"
            subprocess.run(cmd, shell=True, check=True)
            print(f"tfsec 스캔 완료. 결과가 {output_file}에 저장되었습니다.")
            
            # 결과 파싱 및 표준 매핑
            with open(output_file, 'r') as f:
                results = json.load(f)
            
            # 표준화된 형식으로 변환
            standardized_results = self._standardize_tfsec_results(results)
            
            return standardized_results
        except subprocess.CalledProcessError as e:
            print(f"tfsec 실행 중 오류 발생: {e}")
            return {"results": [], "error": str(e)}
        except Exception as e:
            print(f"tfsec 스캔 중 오류 발생: {e}")
            return {"results": [], "error": str(e)}
    
    def run_checkov(self):
        """Checkov 도구를 사용하여 Terraform 코드 스캔"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.output_dir, f'checkov_results_{timestamp}.json')
        
        try:
            # Checkov 실행 (JSON 형식으로 결과 출력)
            cmd = f"checkov -d {self.terraform_dir} --output json --output-file {output_file}"
            subprocess.run(cmd, shell=True, check=True)
            print(f"Checkov 스캔 완료. 결과가 {output_file}에 저장되었습니다.")
            
            # 결과 파싱 및 표준 매핑
            with open(output_file, 'r') as f:
                results = json.load(f)
            
            # 표준화된 형식으로 변환
            standardized_results = self._standardize_checkov_results(results)
            
            return standardized_results
        except subprocess.CalledProcessError as e:
            print(f"Checkov 실행 중 오류 발생: {e}")
            return {"results": [], "error": str(e)}
        except Exception as e:
            print(f"Checkov 스캔 중 오류 발생: {e}")
            return {"results": [], "error": str(e)}
    
    def run_terrascan(self):
        """Terrascan 도구를 사용하여 Terraform 코드 스캔"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.output_dir, f'terrascan_results_{timestamp}.json')
        
        try:
            # Terrascan 실행 (JSON 형식으로 결과 출력)
            cmd = f"terrascan scan -d {self.terraform_dir} -o json > {output_file}"
            subprocess.run(cmd, shell=True, check=True)
            print(f"Terrascan 스캔 완료. 결과가 {output_file}에 저장되었습니다.")
            
            # 결과 파싱 및 표준 매핑
            with open(output_file, 'r') as f:
                results = json.load(f)
            
            # 표준화된 형식으로 변환
            standardized_results = self._standardize_terrascan_results(results)
            
            return standardized_results
        except subprocess.CalledProcessError as e:
            print(f"Terrascan 실행 중 오류 발생: {e}")
            return {"results": [], "error": str(e)}
        except Exception as e:
            print(f"Terrascan 스캔 중 오류 발생: {e}")
            return {"results": [], "error": str(e)}
    
    def run_mock_scan(self):
        """실제 도구 없이 모의 스캔 결과 생성 (테스트 용도)"""
        print("모의 스캔 실행 중...")
        
        # 예제 tfsec 결과
        mock_tfsec_results = {
            "tool": "tfsec",
            "results": [
                {
                    "rule_id": "aws-s3-no-public-access-with-acl",
                    "description": "S3 버킷이 ACL로 공개 액세스 허용",
                    "severity": "CRITICAL",
                    "resource": "aws_s3_bucket.example",
                    "file": "main.tf",
                    "line_start": 7,
                    "line_end": 7
                },
                {
                    "rule_id": "aws-ec2-enforce-http-token-imds",
                    "description": "EC2 인스턴스가 IMDSv2를 강제하지 않음",
                    "severity": "MEDIUM",
                    "resource": "aws_instance.web",
                    "file": "main.tf",
                    "line_start": 11,
                    "line_end": 14
                }
            ]
        }
        
        # 예제 checkov 결과
        mock_checkov_results = {
            "tool": "checkov",
            "results": [
                {
                    "rule_id": "CKV_AWS_20",
                    "description": "S3 버킷이 공개 액세스 허용",
                    "severity": "CRITICAL",
                    "resource": "aws_s3_bucket.example",
                    "file": "main.tf",
                    "line_start": 7,
                    "line_end": 7
                },
                {
                    "rule_id": "CKV_AWS_18",
                    "description": "S3 버킷에 액세스 로깅이 활성화되지 않음",
                    "severity": "HIGH",
                    "resource": "aws_s3_bucket.example",
                    "file": "main.tf",
                    "line_start": 6,
                    "line_end": 9
                }
            ]
        }
        
        # 예제 terrascan 결과
        mock_terrascan_results = {
            "tool": "terrascan",
            "results": [
                {
                    "rule_id": "AC_AWS_0207",
                    "description": "S3 버킷 공개 액세스가 활성화됨",
                    "severity": "HIGH",
                    "resource": "aws_s3_bucket.example",
                    "file": "main.tf",
                    "line_start": 7,
                    "line_end": 7
                }
            ]
        }
        
        return {
            "tfsec": mock_tfsec_results, 
            "checkov": mock_checkov_results,
            "terrascan": mock_terrascan_results
        }
    
    def _standardize_tfsec_results(self, results):
        """tfsec 결과를 표준 형식으로 변환"""
        standardized = {
            "tool": "tfsec",
            "results": []
        }
        
        for result in results.get("results", []):
            rule_id = result.get("rule_id", "")
            
            # 심각도 매핑 (실제 구현에서는 보안 표준 기반으로 확장)
            severity = result.get("severity", "MEDIUM").upper()
            
            standardized_result = {
                "rule_id": rule_id,
                "description": result.get("description", ""),
                "severity": severity,
                "severity_level": self.security_standards.SEVERITY_LEVELS.get(severity, 2),
                "resource": result.get("location", {}).get("resource", ""),
                "file": result.get("location", {}).get("filename", ""),
                "line_start": result.get("location", {}).get("start_line", 0),
                "line_end": result.get("location", {}).get("end_line", 0),
            }
            
            standardized["results"].append(standardized_result)
        
        return standardized
    
    def _standardize_checkov_results(self, results):
        """Checkov 결과를 표준 형식으로 변환"""
        standardized = {
            "tool": "checkov",
            "results": []
        }
        
        # Checkov 결과 구조 처리
        for check_type, checks in results.get("results", {}).get("failed_checks", []):
            for check in checks:
                rule_id = check.get("check_id", "")
                
                # 심각도 매핑
                severity = check.get("severity", "").upper()
                if not severity:
                    severity = "MEDIUM"  # 기본값
                
                standardized_result = {
                    "rule_id": rule_id,
                    "description": check.get("check_name", ""),
                    "severity": severity,
                    "severity_level": self.security_standards.SEVERITY_LEVELS.get(severity, 2),
                    "resource": check.get("resource", ""),
                    "file": check.get("file_path", ""),
                    "line_start": check.get("file_line_range", [0, 0])[0],
                    "line_end": check.get("file_line_range", [0, 0])[1],
                }
                
                standardized["results"].append(standardized_result)
        
        return standardized
    
    def _standardize_terrascan_results(self, results):
        """Terrascan 결과를 표준 형식으로 변환"""
        standardized = {
            "tool": "terrascan",
            "results": []
        }
        
        for violation in results.get("violations", []):
            rule_id = violation.get("rule_id", "")
            
            # 심각도 매핑
            severity = violation.get("severity", "").upper()
            if not severity or severity not in self.security_standards.SEVERITY_LEVELS:
                severity = "MEDIUM"  # 기본값
            
            standardized_result = {
                "rule_id": rule_id,
                "description": violation.get("description", ""),
                "severity": severity,
                "severity_level": self.security_standards.SEVERITY_LEVELS.get(severity, 2),
                "resource": violation.get("resource_name", ""),
                "file": violation.get("file", ""),
                "line_start": violation.get("line", 0),
                "line_end": violation.get("line", 0),
            }
            
            standardized["results"].append(standardized_result)
        
        return standardized
    
    def run_all_scans(self, use_mock=False):
        """모든 스캔 도구 실행"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        print(f"\n==== Terraform 보안 스캔 시작: {timestamp} ====")
        
        try:
            # 실제 스캔 또는 모의 스캔 실행
            if use_mock:
                mock_results = self.run_mock_scan()
                tfsec_results = mock_results["tfsec"]
                checkov_results = mock_results["checkov"]
                terrascan_results = mock_results["terrascan"]
            else:
                try:
                    tfsec_results = self.run_tfsec()
                    checkov_results = self.run_checkov()
                    terrascan_results = self.run_terrascan()
                except Exception as e:
                    print(f"실제 스캔 도구 실행 실패, 모의 스캔으로 대체합니다: {e}")
                    mock_results = self.run_mock_scan()
                    tfsec_results = mock_results["tfsec"]
                    checkov_results = mock_results["checkov"]
                    terrascan_results = mock_results["terrascan"]
            
            # 모든 결과 통합
            combined_results = {
                "timestamp": timestamp,
                "terraform_dir": self.terraform_dir,
                "scan_tools": {
                    "tfsec": tfsec_results,
                    "checkov": checkov_results,
                    "terrascan": terrascan_results
                }
            }
            
            # 심각한 취약점 필터링
            critical_findings = self._filter_critical_findings(combined_results)
            combined_results["critical_findings"] = critical_findings
            combined_results["has_critical"] = len(critical_findings) > 0
            
            # NIST 800-53 기준으로 등급화
            grader = NISTGrader()
            nist_graded_results = grader.grade_findings(combined_results)
            combined_results["nist_graded"] = nist_graded_results
            
            # 배포 차단 여부 결정
            should_block = grader.should_block_deployment(
                nist_graded_results,
                block_on_critical=True,
                block_on_high=False
            )
            combined_results["should_block_deployment"] = should_block
            
            # 통합 결과 저장
            output_file = os.path.join(self.output_dir, f'combined_results_{timestamp}.json')
            with open(output_file, 'w') as f:
                json.dump(combined_results, f, indent=2)
            
            print(f"\n==== Terraform 보안 스캔 완료 ====")
            print(f"통합 결과가 {output_file}에 저장되었습니다.")
            
            # 심각한 취약점이 있을 경우 알림 전송
            if combined_results["has_critical"]:
                critical_count = len(critical_findings)
                print(f"\n⚠️ 경고: {critical_count}개의 심각한 취약점이 발견되었습니다.")
                
                # 알림 전송
                subject = f"심각한 보안 취약점 발견: {critical_count}개"
                message = f"Terraform 코드 스캔 결과, {critical_count}개의 심각한 취약점이 발견되었습니다.\n"
                message += f"파일 경로: {self.terraform_dir}\n"
                message += f"전체 보고서: {output_file}\n"
                
                self.notification_manager.send_alert(
                    subject=subject,
                    message=message,
                    findings=critical_findings,
                    block_deployment=should_block
                )
            
            return combined_results
        
        except Exception as e:
            print(f"스캔 중 오류 발생: {e}")
            return {
                "timestamp": timestamp,
                "terraform_dir": self.terraform_dir,
                "error": str(e),
                "has_critical": False,
                "critical_findings": [],
                "scan_tools": {}
            }
    
    def _filter_critical_findings(self, combined_results):
        """심각한 취약점 필터링"""
        critical_findings = []
        
        # 각 도구의 결과에서 심각한 취약점 추출
        for tool, results in combined_results["scan_tools"].items():
            for finding in results.get("results", []):
                severity = finding.get("severity", "")
                if severity in ["CRITICAL", "HIGH"]:
                    finding["tool"] = tool
                    critical_findings.append(finding)
        
        return critical_findings