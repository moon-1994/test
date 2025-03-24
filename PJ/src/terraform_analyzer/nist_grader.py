from src.terraform_analyzer.security_standards import SecurityStandards

class NISTGrader:
    """NIST 800-53 기준으로 보안 취약점 등급화"""
    
    def __init__(self):
        self.security_standards = SecurityStandards()
    
    def grade_findings(self, scan_results):
        """스캔 결과를 NIST 800-53 기준으로 등급화"""
        graded_results = {
            'summary': {
                'total_findings': 0,
                'critical_findings': 0,
                'high_findings': 0,
                'medium_findings': 0,
                'low_findings': 0,
                'nist_controls': {},
                'overall_risk_score': 0
            },
            'findings': []
        }
        
        # 각 도구별 결과 처리
        for tool, tool_results in scan_results.get("scan_tools", {}).items():
            for finding in tool_results.get("results", []):
                rule_id = finding.get("rule_id", "")
                
                if not rule_id:
                    continue
                
                # NIST 매핑 정보 가져오기
                nist_mapping = self.security_standards.map_tool_rule(tool, rule_id)
                
                # 심각도 결정 (도구 보고 심각도와 매핑된 심각도 중 더 높은 값 선택)
                tool_severity = finding.get("severity", "MEDIUM")
                mapped_severity = nist_mapping['severity']
                
                tool_severity_level = self.security_standards.SEVERITY_LEVELS.get(tool_severity, 2)
                mapped_severity_level = self.security_standards.SEVERITY_LEVELS.get(mapped_severity, 2)
                
                final_severity = tool_severity if tool_severity_level >= mapped_severity_level else mapped_severity
                
                # 영향도 계산
                nist_control = nist_mapping['nist_control']
                impact = self.security_standards.get_nist_impact(nist_control)
                
                # 등급화된 결과에 추가
                graded_finding = {
                    'tool': tool,
                    'rule_id': rule_id,
                    'description': finding.get('description', ''),
                    'resource': finding.get('resource', ''),
                    'file': finding.get('file', ''),
                    'line_start': finding.get('line_start', 0),
                    'severity': final_severity,
                    'severity_level': self.security_standards.SEVERITY_LEVELS.get(final_severity, 2),
                    'nist_control': nist_control,
                    'nist_description': nist_mapping['control_description'],
                    'nist_family': nist_mapping['control_family_name'],
                    'impact_score': impact
                }
                
                graded_results['findings'].append(graded_finding)
                
                # 요약 정보 업데이트
                graded_results['summary']['total_findings'] += 1
                severity_key = f"{final_severity.lower()}_findings"
                graded_results['summary'][severity_key] = graded_results['summary'].get(severity_key, 0) + 1
                
                # NIST 통제 항목별 카운트
                if nist_control not in graded_results['summary']['nist_controls']:
                    graded_results['summary']['nist_controls'][nist_control] = {
                        'count': 0,
                        'description': nist_mapping['control_description'],
                        'family': nist_mapping['control_family_name'],
                        'impact': impact
                    }
                
                graded_results['summary']['nist_controls'][nist_control]['count'] += 1
                
                # 전체 위험 점수 계산 (심각도와 영향도 고려)
                severity_weight = self.security_standards.SEVERITY_LEVELS.get(final_severity, 2)
                graded_results['summary']['overall_risk_score'] += severity_weight * impact
        
        # 위험 점수 정규화 (0-100 범위)
        if graded_results['summary']['total_findings'] > 0:
            max_possible_score = 4 * 10 * graded_results['summary']['total_findings']  # 최대 심각도 * 최대 영향도 * 취약점 수
            graded_results['summary']['overall_risk_score'] = min(100, 
                int((graded_results['summary']['overall_risk_score'] / max_possible_score) * 100))
        
        # 심각한 취약점 존재 여부
        graded_results['summary']['has_critical_findings'] = graded_results['summary'].get('critical_findings', 0) > 0
        graded_results['summary']['has_high_findings'] = graded_results['summary'].get('high_findings', 0) > 0
        
        # 조직 위험 등급 결정
        risk_score = graded_results['summary']['overall_risk_score']
        if risk_score >= 75:
            graded_results['summary']['risk_level'] = 'CRITICAL'
        elif risk_score >= 50:
            graded_results['summary']['risk_level'] = 'HIGH'
        elif risk_score >= 25:
            graded_results['summary']['risk_level'] = 'MEDIUM'
        else:
            graded_results['summary']['risk_level'] = 'LOW'
        
        return graded_results
    
    def should_block_deployment(self, graded_results, block_on_critical=True, block_on_high=False):
        """배포를 차단해야 하는지 결정"""
        if block_on_critical and graded_results['summary'].get('has_critical_findings', False):
            return True
            
        if block_on_high and graded_results['summary'].get('has_high_findings', False):
            return True
            
        return False