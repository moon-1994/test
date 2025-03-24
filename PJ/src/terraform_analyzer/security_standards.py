class SecurityStandards:
    """
    NIST 800-53, OWASP Cloud Security Top 10, MITRE ATT&CK Cloud, Terraform 모범 사례 및 
    CIS Benchmarks에 기반한 보안 취약점 등급화 기준
    """
    
    # 취약점 심각도 레벨
    SEVERITY_LEVELS = {
        'CRITICAL': 4,  # 즉시 대응 필요, 배포 차단
        'HIGH': 3,      # 높은 위험, 배포 차단
        'MEDIUM': 2,    # 중간 위험, 주의 필요
        'LOW': 1,       # 낮은 위험, 참고용
        'INFO': 0       # 정보성, 참고용
    }
    
    # NIST 800-53 주요 통제 영역
    NIST_CONTROLS = {
        'AC': 'Access Control',
        'AU': 'Audit and Accountability',
        'AT': 'Awareness and Training',
        'CM': 'Configuration Management',
        'CP': 'Contingency Planning',
        'IA': 'Identification and Authentication',
        'IR': 'Incident Response',
        'MA': 'Maintenance',
        'MP': 'Media Protection',
        'PS': 'Personnel Security',
        'PE': 'Physical and Environmental Protection',
        'PL': 'Planning',
        'PM': 'Program Management',
        'RA': 'Risk Assessment',
        'CA': 'Security Assessment and Authorization',
        'SC': 'System and Communications Protection',
        'SI': 'System and Information Integrity'
    }
    
    # NIST 800-53 상세 통제 항목
    NIST_SPECIFIC_CONTROLS = {
        'AC-3': 'Access Enforcement',
        'AC-6': 'Least Privilege',
        'AC-17': 'Remote Access',
        'AU-2': 'Audit Events',
        'AU-9': 'Protection of Audit Information',
        'CM-2': 'Baseline Configuration',
        'IA-2': 'Identification and Authentication',
        'IA-5': 'Authenticator Management',
        'SC-8': 'Transmission Confidentiality and Integrity',
        'SC-12': 'Cryptographic Key Establishment and Management',
        'SC-13': 'Cryptographic Protection',
        'SC-28': 'Protection of Information at Rest',
        'SI-4': 'Information System Monitoring',
        'SI-7': 'Software, Firmware, and Information Integrity'
    }
    
    # 도구별 규칙 ID와 NIST 800-53 통제 항목 매핑
    TOOL_MAPPINGS = {
        # tfsec 규칙
        'tfsec': {
            'aws-s3-enable-bucket-encryption': {
                'nist_control': 'SC-28',
                'severity': 'HIGH',
                'description': 'S3 버킷이 암호화되지 않음'
            },
            'aws-s3-no-public-access-with-acl': {
                'nist_control': 'AC-3',
                'severity': 'CRITICAL',
                'description': 'S3 버킷이 ACL로 공개 액세스 허용'
            },
            'aws-iam-no-policy-wildcards': {
                'nist_control': 'AC-6',
                'severity': 'HIGH',
                'description': 'IAM 정책에 와일드카드(*) 권한 사용'
            },
            'aws-ec2-enforce-http-token-imds': {
                'nist_control': 'IA-5',
                'severity': 'MEDIUM',
                'description': 'EC2 인스턴스가 IMDSv2를 강제하지 않음'
            }
        },
        
        # Checkov 규칙
        'checkov': {
            'CKV_AWS_18': {
                'nist_control': 'AU-2',
                'severity': 'HIGH',
                'description': 'S3 버킷에 액세스 로깅이 활성화되지 않음'
            },
            'CKV_AWS_20': {
                'nist_control': 'AC-3',
                'severity': 'CRITICAL',
                'description': 'S3 버킷이 ACL로 공개 액세스 허용'
            },
            'CKV_AWS_24': {
                'nist_control': 'SC-28',
                'severity': 'HIGH',
                'description': 'S3 버킷 암호화가 활성화되지 않음'
            },
            'CKV_AWS_40': {
                'nist_control': 'IA-5',
                'severity': 'MEDIUM',
                'description': 'IAM 암호 정책이 재사용을 방지하지 않음'
            }
        },
        
        # Terrascan 규칙
        'terrascan': {
            'AC_AWS_0207': {
                'nist_control': 'AC-3',
                'severity': 'HIGH',
                'description': 'S3 버킷 공개 액세스가 활성화됨'
            },
            'AC_AWS_0014': {
                'nist_control': 'AC-6',
                'severity': 'HIGH',
                'description': 'IAM 정책에 관리 권한이 과도하게 부여됨'
            },
            'AC_AWS_0057': {
                'nist_control': 'SC-28',
                'severity': 'MEDIUM',
                'description': 'RDS 데이터베이스가 암호화되지 않음'
            }
        }
    }
    
    @staticmethod
    def map_tool_rule(tool, rule_id):
        """도구별 규칙 ID를 NIST 800-53 통제 항목에 매핑"""
        if tool in SecurityStandards.TOOL_MAPPINGS and rule_id in SecurityStandards.TOOL_MAPPINGS[tool]:
            mapping = SecurityStandards.TOOL_MAPPINGS[tool][rule_id]
            nist_control = mapping['nist_control']
            
            # 통제 영역(대분류) 추출
            control_family = nist_control.split('-')[0] if '-' in nist_control else nist_control
            
            return {
                'nist_control': nist_control,
                'control_description': SecurityStandards.NIST_SPECIFIC_CONTROLS.get(nist_control, ''),
                'control_family': control_family,
                'control_family_name': SecurityStandards.NIST_CONTROLS.get(control_family, ''),
                'severity': mapping['severity'],
                'description': mapping['description']
            }
        
        # 매핑되지 않은 규칙은 기본값 반환
        return {
            'nist_control': 'Unknown',
            'control_description': '',
            'control_family': '',
            'control_family_name': '',
            'severity': 'MEDIUM',
            'description': ''
        }
    
    @staticmethod
    def get_nist_impact(nist_control):
        """NIST 통제 항목별 영향도 점수 반환"""
        # 영향도 점수 정의 (1-10 범위, 높을수록 중요)
        impact_scores = {
            'AC-3': 10,  # 접근 제어 시행
            'AC-6': 9,   # 최소 권한
            'SC-28': 8,  # 저장 정보 보호
            'IA-5': 8,   # 인증자 관리
            'AU-2': 7,   # 감사 이벤트
            'SC-8': 7,   # 전송 중 보호
            'IA-2': 8,   # 식별 및 인증
            'SI-4': 7    # 시스템 모니터링
        }
        
        return impact_scores.get(nist_control, 5)  # 기본값은 5