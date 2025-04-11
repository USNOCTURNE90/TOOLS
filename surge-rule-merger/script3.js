    // 恢复被删除的规则
    function restoreRule(rule) {
        // 从已删除列表中移除
        const index = removedRulesList.findIndex(r => r.original === rule.original);
        if (index !== -1) {
            removedRulesList.splice(index, 1);
        }
        
        // 添加到合并列表
        mergedRulesList.push(rule);
        
        // 更新统计和显示
        updateStats();
        sortRules();
        updateOutputDisplay();
        
        // 更新详情显示
        const details = detailOutput.innerHTML;
        detailOutput.innerHTML = details.replace(
            `<span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule))}">${rule.original}</span>`,
            `<span>${rule.original}</span> (已恢复)`
        );
    }
    
    // 排序规则
    function sortRules() {
        const method = sortMethod.value;
        
        if (method === 'none') {
            return; // 不排序
        }
        
        // 按类型分组
        const grouped = {};
        mergedRulesList.forEach(rule => {
            if (!grouped[rule.type]) {
                grouped[rule.type] = [];
            }
            grouped[rule.type].push(rule);
        });
        
        // 对每种规则类型应用排序
        for (const type in grouped) {
            if (type === 'IP-CIDR' || type === 'IP-CIDR6') {
                if (method === 'ip') {
                    // IP按数字大小排序
                    grouped[type].sort((a, b) => {
                        const [ipA, bitsA] = a.value.split('/');
                        const [ipB, bitsB] = b.value.split('/');
                        
                        // 先按掩码排序
                        if (bitsA !== bitsB) {
                            return parseInt(bitsA) - parseInt(bitsB);
                        }
                        
                        // 再按IP大小排序
                        return ipCidrTools.ipToInt(ipA) - ipCidrTools.ipToInt(ipB);
                    });
                } else if (method === 'alpha' || method === 'domain') {
                    // 按字母排序
                    grouped[type].sort((a, b) => a.value.localeCompare(b.value));
                }
            } else if (type.startsWith('DOMAIN')) {
                if (method === 'domain') {
                    // 按域名主体分组排序
                    grouped[type].sort((a, b) => {
                        // 提取域名的主要部分（例如 apple.com, google.com）
                        const getDomainBase = (domain) => {
                            const parts = domain.split('.');
                            if (parts.length >= 2) {
                                return parts[parts.length - 2] + '.' + parts[parts.length - 1];
                            }
                            return domain;
                        };
                        
                        const baseA = getDomainBase(a.value);
                        const baseB = getDomainBase(b.value);
                        
                        // 先按域名主体排序
                        if (baseA !== baseB) {
                            return baseA.localeCompare(baseB);
                        }
                        
                        // 域名主体相同时按完整域名排序
                        return a.value.localeCompare(b.value);
                    });
                } else if (method === 'alpha') {
                    // 按字母排序
                    grouped[type].sort((a, b) => a.value.localeCompare(b.value));
                }
            } else {
                // 其他规则类型按字母排序
                if (method === 'alpha' || method === 'domain') {
                    grouped[type].sort((a, b) => a.value.localeCompare(b.value));
                }
            }
        }
        
        // 重建合并规则列表
        mergedRulesList = [];
        
        // 按顺序添加各类规则
        ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'].forEach(type => {
            if (grouped[type]) {
                mergedRulesList.push(...grouped[type]);
            }
        });
        
        ['IP-CIDR', 'IP-CIDR6', 'GEOIP'].forEach(type => {
            if (grouped[type]) {
                mergedRulesList.push(...grouped[type]);
            }
        });
        
        // 添加其他规则类型
        Object.keys(grouped).forEach(type => {
            if (!['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6', 'GEOIP'].includes(type)) {
                mergedRulesList.push(...grouped[type]);
            }
        });
    }
    
    // 更新输出显示
    function updateOutputDisplay() {
        // 转换回文本格式
        let resultText = '';
        
        if (mergedRulesList.length > 0) {
            const grouped = {};
            
            // 按类型分组
            mergedRulesList.forEach(rule => {
                if (!grouped[rule.type]) {
                    grouped[rule.type] = [];
                }
                grouped[rule.type].push(rule);
            });
            
            // 添加行号计数器
            let lineNumber = 1;
            
            // 按顺序输出域名规则
            ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'].forEach(type => {
                if (grouped[type] && grouped[type].length > 0) {
                    resultText += `# ${type} 规则\n`;
                    lineNumber++;
                    
                    grouped[type].forEach(rule => {
                        resultText += `${lineNumber}. ${rule.original}\n`;
                        lineNumber++;
                    });
                    resultText += '\n';
                    lineNumber++;
                }
            });
            
            // 输出IP规则
            ['IP-CIDR', 'IP-CIDR6', 'GEOIP'].forEach(type => {
                if (grouped[type] && grouped[type].length > 0) {
                    resultText += `# ${type} 规则\n`;
                    lineNumber++;
                    
                    grouped[type].forEach(rule => {
                        resultText += `${lineNumber}. ${rule.original}\n`;
                        lineNumber++;
                    });
                    resultText += '\n';
                    lineNumber++;
                }
            });
            
            // 输出其他规则
            const otherTypes = Object.keys(grouped).filter(type => 
                !['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6', 'GEOIP'].includes(type)
            );
            
            if (otherTypes.length > 0) {
                resultText += '# 其他规则\n';
                lineNumber++;
                
                otherTypes.forEach(type => {
                    if (grouped[type] && grouped[type].length > 0) {
                        grouped[type].forEach(rule => {
                            resultText += `${lineNumber}. ${rule.original}\n`;
                            lineNumber++;
                        });
                    }
                });
            }
        }
        
        // 更新UI
        outputRules.value = resultText;
    }
    
    // 更新统计信息
    function updateStats() {
        const originalRulesCount = allParsedRules.length + ignoredLinesList.length;
        originalCount.textContent = `原始规则数量: ${originalRulesCount}`;
        mergedCount.textContent = `合并后规则数量: ${mergedRulesList.length}`;
        removedCount.textContent = `移除重复/重叠规则数量: ${removedRulesList.length}`;
    } 