    // 合并规则
    function mergeRules() {
        const input = inputRules.value.trim();
        if (!input) {
            alert('请输入规则');
            return;
        }
        
        const lines = input.split('\n');
        const originalRulesCount = lines.length;
        
        // 重置全局列表
        allParsedRules = [];
        mergedRulesList = [];
        removedRulesList = [];
        ignoredLinesList = [];
        
        // 识别注释行和空行
        lines.forEach((line, index) => {
            const trimmedLine = line.trim();
            if (!trimmedLine || trimmedLine.startsWith('#')) {
                ignoredLinesList.push({ index, line });
            }
        });
        
        // 解析所有规则
        allParsedRules = lines
            .map((line, index) => {
                const rule = parseRule(line.trim());
                if (rule === null) {
                    // 如果不是已识别的注释行或空行，但解析失败，也记录下来
                    if (!ignoredLinesList.some(ignored => ignored.index === index)) {
                        ignoredLinesList.push({ index, line, reason: '格式不符' });
                    }
                }
                return rule;
            })
            .filter(rule => rule !== null);
        
        // 按类型分组规则
        const rulesByType = {};
        allParsedRules.forEach(rule => {
            if (!rulesByType[rule.type]) {
                rulesByType[rule.type] = [];
            }
            rulesByType[rule.type].push(rule);
        });
        
        // 详情日志
        let details = '<div class="detail-section">合并详情日志：<br>';
        details += '============<br>';
        details += `原始规则数量：${originalRulesCount}<br>`;
        details += `忽略的行数（空行、注释等）：${ignoredLinesList.length}<br>`;
        details += `有效规则数量：${allParsedRules.length}<br>`;
        details += '============</div><br>';

        // 处理域名规则
        details += '<div class="detail-section">域名规则处理：<br>';
        details += '------------<br>';
        
        // 处理DOMAIN规则
        if (rulesByType['DOMAIN']) {
            details += `<br>发现${rulesByType['DOMAIN'].length}条DOMAIN规则<br>`;
            
            // 去重DOMAIN规则
            const uniqueDomains = {};
            let duplicateCount = 0;
            
            rulesByType['DOMAIN'].forEach(rule => {
                const key = rule.value + '|' + rule.policy;
                if (!uniqueDomains[key]) {
                    uniqueDomains[key] = rule;
                } else {
                    details += `删除重复DOMAIN规则: <span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule))}">${rule.original}</span><br>`;
                    removedRulesList.push(rule);
                    duplicateCount++;
                }
            });
            
            // 将唯一的DOMAIN规则添加到结果
            Object.values(uniqueDomains).forEach(rule => mergedRulesList.push(rule));
            
            details += `DOMAIN规则处理完成，原始: ${rulesByType['DOMAIN'].length}，唯一: ${Object.keys(uniqueDomains).length}，删除重复: ${duplicateCount}<br>`;
        }
        
        // 处理DOMAIN-SUFFIX规则
        if (rulesByType['DOMAIN-SUFFIX']) {
            details += `<br>发现${rulesByType['DOMAIN-SUFFIX'].length}条DOMAIN-SUFFIX规则<br>`;
            
            // 去重并检查DOMAIN-SUFFIX之间的关系
            const suffixRules = [...rulesByType['DOMAIN-SUFFIX']];
            const uniqueSuffixes = [];
            const skippedSuffixes = new Set();
            let containedCount = 0;
            
            // 第一步：排除那些被其他后缀包含的规则
            for (let i = 0; i < suffixRules.length; i++) {
                if (skippedSuffixes.has(i)) continue;
                
                const rule1 = suffixRules[i];
                let isContained = false;
                
                for (let j = 0; j < suffixRules.length; j++) {
                    if (i === j || skippedSuffixes.has(j)) continue;
                    
                    const rule2 = suffixRules[j];
                    // 如果策略不同，不能合并
                    if (rule1.policy !== rule2.policy) continue;
                    
                    const relationship = domainRelationship(rule1.value, rule2.value);
                    
                    if (relationship === 'SUBDOMAIN') {
                        isContained = true;
                        details += `合并: 域名后缀 ${rule1.value} 被 ${rule2.value} 包含，保留 ${rule2.value}<br>`;
                        details += `移除: <span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule1))}">${rule1.original}</span><br>`;
                        removedRulesList.push(rule1);
                        containedCount++;
                        break;
                    }
                }
                
                if (!isContained) {
                    uniqueSuffixes.push(rule1);
                } else {
                    skippedSuffixes.add(i);
                }
            }
            
            // 将唯一的DOMAIN-SUFFIX规则添加到结果
            uniqueSuffixes.forEach(rule => mergedRulesList.push(rule));
            
            details += `DOMAIN-SUFFIX规则处理完成，原始: ${suffixRules.length}，唯一: ${uniqueSuffixes.length}，删除包含关系: ${containedCount}<br>`;
        }
    } 