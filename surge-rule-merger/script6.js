        // 处理IP-CIDR规则
        if (rulesByType['IP-CIDR']) {
            details += `<br>发现${rulesByType['IP-CIDR'].length}条IP-CIDR规则<br>`;
            
            const cidrRules = [...rulesByType['IP-CIDR']];
            const mergedCidrRules = [];
            
            // 对同一策略的CIDR进行排序和合并
            const cidrsByPolicy = {};
            cidrRules.forEach(rule => {
                if (!cidrsByPolicy[rule.policy]) {
                    cidrsByPolicy[rule.policy] = [];
                }
                cidrsByPolicy[rule.policy].push(rule);
            });
            
            // 处理每个策略组的CIDR
            for (const policy in cidrsByPolicy) {
                details += `<br>处理策略 "${policy}" 下的IP-CIDR规则<br>`;
                
                const policyCidrs = cidrsByPolicy[policy];
                const processedCidrs = new Set();
                
                // 第一步：去除被其他CIDR完全包含的子网
                for (let i = 0; i < policyCidrs.length; i++) {
                    const rule1 = policyCidrs[i];
                    if (processedCidrs.has(i)) continue;
                    
                    let isContained = false;
                    
                    for (let j = 0; j < policyCidrs.length; j++) {
                        if (i === j || processedCidrs.has(j)) continue;
                        
                        const rule2 = policyCidrs[j];
                        
                        try {
                            if (ipCidrTools.cidrContains(rule2.value, rule1.value)) {
                                isContained = true;
                                details += `合并: IP-CIDR ${rule1.value} 被 ${rule2.value} 包含，保留 ${rule2.value}<br>`;
                                details += `移除: <span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule1))}">${rule1.original}</span><br>`;
                                removedRulesList.push(rule1);
                                processedCidrs.add(i);
                                break;
                            }
                        } catch (e) {
                            details += `错误: 处理IP-CIDR时出错 ${e.message}<br>`;
                        }
                    }
                    
                    if (!isContained) {
                        mergedCidrRules.push(rule1);
                    }
                }
                
                // 第二步：尝试合并相邻的CIDR
                let hasMerged = true;
                let currentCidrs = [...mergedCidrRules.filter(r => r.policy === policy)];
                let iterationCount = 0; // 记录迭代次数，以防无限循环
                
                while (hasMerged && currentCidrs.length > 1 && iterationCount < 10) {
                    iterationCount++;
                    hasMerged = false;
                    
                    const nextCidrs = [];
                    const processed = new Set();
                    
                    details += `<br>合并CIDR迭代 #${iterationCount}, 当前规则数: ${currentCidrs.length}<br>`;
                    
                    for (let i = 0; i < currentCidrs.length; i++) {
                        if (processed.has(i)) continue;
                        
                        const rule1 = currentCidrs[i];
                        let merged = false;
                        
                        for (let j = i + 1; j < currentCidrs.length; j++) {
                            if (processed.has(j)) continue;
                            
                            const rule2 = currentCidrs[j];
                            
                            try {
                                const mergedCidr = ipCidrTools.mergeCidrs(rule1.value, rule2.value);
                                
                                if (mergedCidr) {
                                    hasMerged = true;
                                    merged = true;
                                    processed.add(i);
                                    processed.add(j);
                                    
                                    const newRule = { 
                                        type: 'IP-CIDR', 
                                        value: mergedCidr, 
                                        policy: rule1.policy,
                                        original: `IP-CIDR,${mergedCidr},${rule1.policy}`
                                    };
                                    
                                    nextCidrs.push(newRule);
                                    details += `合并: ${rule1.value} + ${rule2.value} => ${mergedCidr}<br>`;
                                    
                                    // 标记这两条规则被合并了
                                    details += `移除: <span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule1))}">${rule1.original}</span><br>`;
                                    details += `移除: <span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule2))}">${rule2.original}</span><br>`;
                                    
                                    if (!removedRulesList.includes(rule1)) removedRulesList.push(rule1);
                                    if (!removedRulesList.includes(rule2)) removedRulesList.push(rule2);
                                    break;
                                }
                            } catch (e) {
                                details += `错误: 合并IP-CIDR时出错 ${e.message}<br>`;
                            }
                        }
                        
                        if (!merged) {
                            nextCidrs.push(rule1);
                        }
                    }
                    
                    currentCidrs = nextCidrs;
                }
                
                // 更新合并后的CIDR规则
                const cidrRulesToKeep = mergedCidrRules.filter(r => r.policy !== policy);
                mergedCidrRules.length = 0;
                mergedCidrRules.push(...cidrRulesToKeep);
                mergedCidrRules.push(...currentCidrs);
            }
            
            // 将合并后的IP-CIDR规则添加到结果
            mergedRulesList.push(...mergedCidrRules);
            
            details += `<br>IP-CIDR规则处理完成，原始规则: ${cidrRules.length}，合并后: ${mergedCidrRules.length}，移除: ${cidrRules.length - mergedCidrRules.length}<br>`;
        }
        
        details += '</div>';
        
        // 处理其他类型的规则
        const processedTypes = ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR'];
        const otherRules = allParsedRules.filter(rule => !processedTypes.includes(rule.type));
        
        if (otherRules.length > 0) {
            details += '<div class="detail-section">其他类型规则处理：<br>';
            details += '----------------<br>';
            details += `发现${otherRules.length}条其他类型规则，进行简单去重<br>`;
            
            // 简单去重
            const uniqueOtherRules = {};
            let duplicateCount = 0;
            
            otherRules.forEach(rule => {
                const key = rule.original;
                if (!uniqueOtherRules[key]) {
                    uniqueOtherRules[key] = rule;
                } else {
                    details += `删除重复规则: <span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule))}">${rule.original}</span><br>`;
                    removedRulesList.push(rule);
                    duplicateCount++;
                }
            });
            
            // 将其他类型的规则添加到结果
            Object.values(uniqueOtherRules).forEach(rule => mergedRulesList.push(rule));
            
            details += `其他规则处理完成，原始: ${otherRules.length}，唯一: ${Object.keys(uniqueOtherRules).length}，删除重复: ${duplicateCount}<br>`;
            details += '</div>';
        } 