        // 处理DOMAIN-KEYWORD规则
        if (rulesByType['DOMAIN-KEYWORD']) {
            details += `<br>发现${rulesByType['DOMAIN-KEYWORD'].length}条DOMAIN-KEYWORD规则<br>`;
            
            // 去重DOMAIN-KEYWORD规则
            const uniqueKeywords = {};
            let duplicateCount = 0;
            
            rulesByType['DOMAIN-KEYWORD'].forEach(rule => {
                const key = rule.value + '|' + rule.policy;
                if (!uniqueKeywords[key]) {
                    uniqueKeywords[key] = rule;
                } else {
                    details += `删除重复DOMAIN-KEYWORD规则: <span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule))}">${rule.original}</span><br>`;
                    removedRulesList.push(rule);
                    duplicateCount++;
                }
            });
            
            // 将唯一的DOMAIN-KEYWORD规则添加到结果
            Object.values(uniqueKeywords).forEach(rule => mergedRulesList.push(rule));
            
            // 检查KEYWORD是否已被其他规则包含
            const keywordRules = [...Object.values(uniqueKeywords)];
            const finalKeywordRules = [];
            let containedCount = 0;
            
            keywordRules.forEach(keywordRule => {
                // 如果某个DOMAIN-SUFFIX包含此关键词，则可以删除
                let isRedundant = false;
                
                // 检查是否被DOMAIN-SUFFIX包含
                if (rulesByType['DOMAIN-SUFFIX']) {
                    for (const suffixRule of mergedRulesList.filter(r => r.type === 'DOMAIN-SUFFIX')) {
                        if (suffixRule.policy !== keywordRule.policy) continue;
                        
                        if (suffixRule.value.includes(keywordRule.value)) {
                            isRedundant = true;
                            details += `DOMAIN-KEYWORD: ${keywordRule.value} 已被 DOMAIN-SUFFIX: ${suffixRule.value} 包含，删除<br>`;
                            details += `移除: <span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(keywordRule))}">${keywordRule.original}</span><br>`;
                            removedRulesList.push(keywordRule);
                            containedCount++;
                            break;
                        }
                    }
                }
                
                if (!isRedundant) {
                    finalKeywordRules.push(keywordRule);
                }
            });
            
            // 更新合并的规则列表
            // 先移除所有DOMAIN-KEYWORD规则
            const nonKeywordRules = mergedRulesList.filter(rule => rule.type !== 'DOMAIN-KEYWORD');
            mergedRulesList.length = 0;
            // 然后添加保留的DOMAIN-KEYWORD规则和其他规则
            mergedRulesList.push(...finalKeywordRules);
            mergedRulesList.push(...nonKeywordRules);
            
            details += `DOMAIN-KEYWORD规则处理完成，原始: ${rulesByType['DOMAIN-KEYWORD'].length}，去重后: ${keywordRules.length}，最终保留: ${finalKeywordRules.length}，移除重复: ${duplicateCount}，移除冗余: ${containedCount}<br>`;
        }
        
        // 处理DOMAIN和DOMAIN-SUFFIX之间的关系
        if (rulesByType['DOMAIN'] && rulesByType['DOMAIN-SUFFIX']) {
            details += '<br>检查DOMAIN与DOMAIN-SUFFIX之间的关系<br>';
            
            const domainsToKeep = [];
            let containedCount = 0;
            
            for (const domainRule of mergedRulesList.filter(r => r.type === 'DOMAIN')) {
                let isContained = false;
                
                for (const suffixRule of mergedRulesList.filter(r => r.type === 'DOMAIN-SUFFIX')) {
                    if (domainRule.policy !== suffixRule.policy) continue;
                    
                    // 检查domain是否匹配suffix
                    if (domainRule.value === suffixRule.value || 
                        domainRule.value.endsWith('.' + suffixRule.value)) {
                            isContained = true;
                            details += `DOMAIN: ${domainRule.value} 已被 DOMAIN-SUFFIX: ${suffixRule.value} 包含，删除<br>`;
                            details += `移除: <span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(domainRule))}">${domainRule.original}</span><br>`;
                            removedRulesList.push(domainRule);
                            containedCount++;
                            break;
                    }
                }
                
                if (!isContained) {
                    domainsToKeep.push(domainRule);
                }
            }
            
            // 更新合并的规则列表
            const otherRulesExceptDomain = mergedRulesList.filter(rule => rule.type !== 'DOMAIN');
            mergedRulesList.length = 0;
            mergedRulesList.push(...domainsToKeep);
            mergedRulesList.push(...otherRulesExceptDomain);
            
            details += `DOMAIN与DOMAIN-SUFFIX关系处理完成，移除被包含的DOMAIN规则: ${containedCount}<br>`;
        }
        
        details += '</div>';
        
        // 处理IP规则
        details += '<div class="detail-section">IP规则处理：<br>';
        details += '------------<br>'; 