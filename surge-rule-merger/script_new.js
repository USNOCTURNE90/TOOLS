document.addEventListener('DOMContentLoaded', function() {
    // 获取DOM元素
    const inputRules = document.getElementById('input-rules');
    const outputRules = document.getElementById('output-rules');
    const detailOutput = document.getElementById('detail-output');
    const inputLineNumbers = document.getElementById('input-line-numbers');
    const mergeBtn = document.getElementById('merge-btn');
    const clearBtn = document.getElementById('clear-btn');
    const exampleBtn = document.getElementById('example-btn');
    const copyBtn = document.getElementById('copy-btn');
    const downloadBtn = document.getElementById('download-btn');
    const copyDetailBtn = document.getElementById('copy-detail-btn');
    const clearDetailBtn = document.getElementById('clear-detail-btn');
    const originalCount = document.getElementById('original-count');
    const mergedCount = document.getElementById('merged-count');
    const removedCount = document.getElementById('removed-count');
    const sortMethod = document.getElementById('sort-method');
    const applySort = document.getElementById('apply-sort');
    
    // 存储所有规�?
    let allParsedRules = [];
    let mergedRulesList = [];
    let removedRulesList = [];
    let ignoredLinesList = [];

    // 初始化行号显�?
    updateLineNumbers();

    // 监听输入变化以更新行�?
    inputRules.addEventListener('input', updateLineNumbers);
    inputRules.addEventListener('scroll', syncScroll);
    
    // 绑定排序按钮
    applySort.addEventListener('click', function() {
        if (mergedRulesList.length > 0) {
            sortRules();
            updateOutputDisplay();
        }
    });

    // 同步滚动
    function syncScroll() {
        inputLineNumbers.scrollTop = inputRules.scrollTop;
    }

    // 更新行号显示
    function updateLineNumbers() {
        const lines = inputRules.value.split('\n');
        let lineNumbersHtml = '';
        
        for (let i = 0; i < lines.length; i++) {
            lineNumbersHtml += `<div>${i + 1}</div>`;
        }
        
        // 确保至少有一�?
        if (lines.length === 0 || (lines.length === 1 && lines[0] === '')) {
            lineNumbersHtml = '<div>1</div>';
        }
        
        inputLineNumbers.innerHTML = lineNumbersHtml;
        
        // 调整行号区域的高度以匹配文本区域
        inputLineNumbers.style.height = `${inputRules.scrollHeight}px`;
    }

    // 绑定按钮事件
    mergeBtn.addEventListener('click', mergeRules);
    clearBtn.addEventListener('click', clearInputs);
    exampleBtn.addEventListener('click', loadExample);
    copyBtn.addEventListener('click', () => copyToClipboard(outputRules.value));
    downloadBtn.addEventListener('click', downloadRules);
    copyDetailBtn.addEventListener('click', () => copyToClipboard(detailOutput.innerText));
    clearDetailBtn.addEventListener('click', () => {
        detailOutput.innerHTML = '';
    });
}); 
    // CIDR操作工具
    const ipCidrTools = {
        // 将IP转换为整�?
        ipToInt: function(ip) {
            return ip.split('.')
                .reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
        },

        // 将整数转换回IP
        intToIp: function(int) {
            return [
                (int >>> 24) & 255,
                (int >>> 16) & 255,
                (int >>> 8) & 255,
                int & 255
            ].join('.');
        },

        // 计算CIDR中的掩码
        getCidrMask: function(bits) {
            return ~(Math.pow(2, 32 - bits) - 1) >>> 0;
        },

        // 获取CIDR的第一个IP
        getCidrFirstIp: function(cidr) {
            const [ip, bits] = cidr.split('/');
            const mask = this.getCidrMask(parseInt(bits, 10));
            return this.intToIp(this.ipToInt(ip) & mask);
        },

        // 获取CIDR的最后一个IP
        getCidrLastIp: function(cidr) {
            const [ip, bits] = cidr.split('/');
            const mask = this.getCidrMask(parseInt(bits, 10));
            const invMask = ~mask >>> 0;
            return this.intToIp((this.ipToInt(ip) & mask) | invMask);
        },

        // 检查一个CIDR是否完全包含另一个CIDR
        cidrContains: function(cidr1, cidr2) {
            const [ip1, bits1] = cidr1.split('/');
            const [ip2, bits2] = cidr2.split('/');
            
            const mask1 = this.getCidrMask(parseInt(bits1, 10));
            const ipInt1 = this.ipToInt(ip1) & mask1;
            const ipInt2 = this.ipToInt(ip2);
            
            // 如果掩码2比掩�?小，则不可能包含
            if (parseInt(bits1, 10) > parseInt(bits2, 10)) {
                return false;
            }
            
            // 检查ip2是否在cidr1范围�?
            return (ipInt2 & mask1) === ipInt1;
        },

        // 尝试合并两个CIDR
        canMergeCidrs: function(cidr1, cidr2) {
            const [ip1, bits1] = cidr1.split('/');
            const [ip2, bits2] = cidr2.split('/');
            
            // 如果掩码不同，无法简单合�?
            if (bits1 !== bits2) {
                return false;
            }
            
            const ipInt1 = this.ipToInt(ip1);
            const ipInt2 = this.ipToInt(ip2);
            const bits = parseInt(bits1, 10);
            const mask = this.getCidrMask(bits);
            
            // 检查如果减�?位掩码，两个网络是否会合并成一�?
            const parentMask = this.getCidrMask(bits - 1);
            return (ipInt1 & parentMask) === (ipInt2 & parentMask);
        },
        
        // 合并两个可合并的CIDR
        mergeCidrs: function(cidr1, cidr2) {
            if (!this.canMergeCidrs(cidr1, cidr2)) {
                return null;
            }
            
            const [ip1, bits1] = cidr1.split('/');
            const bits = parseInt(bits1, 10);
            const parentMask = this.getCidrMask(bits - 1);
            
            return this.intToIp(this.ipToInt(ip1) & parentMask) + '/' + (bits - 1);
        }
    };

    // 规则解析和处理函�?
    function parseRule(rule) {
        // 移除注释
        const commentIndex = rule.indexOf('#');
        if (commentIndex !== -1) {
            rule = rule.substring(0, commentIndex).trim();
        }
        
        // 如果为空行则跳过
        if (!rule) {
            return null;
        }
        
        // 分割规则组成部分
        const parts = rule.split(',');
        if (parts.length < 2) {
            // 规则格式不正�?
            return { type: 'UNKNOWN', original: rule };
        }
        
        const type = parts[0];
        const value = parts[1];
        const policy = parts.length > 2 ? parts.slice(2).join(',') : '';
        
        return { type, value, policy, original: rule };
    }

    // 检查域名是否包含或被包�?
    function domainRelationship(domain1, domain2) {
        // 如果完全相同
        if (domain1 === domain2) {
            return 'SAME';
        }
        
        // 检查后缀关系
        if (domain1.endsWith('.' + domain2)) {
            return 'SUBDOMAIN'; // domain1是domain2的子域名
        }
        
        if (domain2.endsWith('.' + domain1)) {
            return 'PARENT'; // domain1是domain2的父域名
        }
        
        return 'UNRELATED';
    } 
    // 恢复被删除的规则
    function restoreRule(rule) {
        // 从已删除列表中移�?
        const index = removedRulesList.findIndex(r => r.original === rule.original);
        if (index !== -1) {
            removedRulesList.splice(index, 1);
        }
        
        // 添加到合并列�?
        mergedRulesList.push(rule);
        
        // 更新统计和显�?
        updateStats();
        sortRules();
        updateOutputDisplay();
        
        // 更新详情显示
        const details = detailOutput.innerHTML;
        detailOutput.innerHTML = details.replace(
            `<span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule))}">${rule.original}</span>`,
            `<span>${rule.original}</span> (已恢�?`
        );
    }
    
    // 排序规则
    function sortRules() {
        const method = sortMethod.value;
        
        if (method === 'none') {
            return; // 不排�?
        }
        
        // 按类型分�?
        const grouped = {};
        mergedRulesList.forEach(rule => {
            if (!grouped[rule.type]) {
                grouped[rule.type] = [];
            }
            grouped[rule.type].push(rule);
        });
        
        // 对每种规则类型应用排�?
        for (const type in grouped) {
            if (type === 'IP-CIDR' || type === 'IP-CIDR6') {
                if (method === 'ip') {
                    // IP按数字大小排�?
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
                    // 按字母排�?
                    grouped[type].sort((a, b) => a.value.localeCompare(b.value));
                }
            } else if (type.startsWith('DOMAIN')) {
                if (method === 'domain') {
                    // 按域名主体分组排�?
                    grouped[type].sort((a, b) => {
                        // 提取域名的主要部分（例如 apple.com, google.com�?
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
                    // 按字母排�?
                    grouped[type].sort((a, b) => a.value.localeCompare(b.value));
                }
            } else {
                // 其他规则类型按字母排�?
                if (method === 'alpha' || method === 'domain') {
                    grouped[type].sort((a, b) => a.value.localeCompare(b.value));
                }
            }
        }
        
        // 重建合并规则列表
        mergedRulesList = [];
        
        // 按顺序添加各类规�?
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
        // 转换回文本格�?
        let resultText = '';
        
        if (mergedRulesList.length > 0) {
            const grouped = {};
            
            // 按类型分�?
            mergedRulesList.forEach(rule => {
                if (!grouped[rule.type]) {
                    grouped[rule.type] = [];
                }
                grouped[rule.type].push(rule);
            });
            
            // 添加行号计数�?
            let lineNumber = 1;
            
            // 按顺序输出域名规�?
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
        mergedCount.textContent = `合并后规则数�? ${mergedRulesList.length}`;
        removedCount.textContent = `移除重复/重叠规则数量: ${removedRulesList.length}`;
    } 
    // 合并规则
    function mergeRules() {
        const input = inputRules.value.trim();
        if (!input) {
            alert('请输入规�?);
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
        
        // 解析所有规�?
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
        
        // 按类型分组规�?
        const rulesByType = {};
        allParsedRules.forEach(rule => {
            if (!rulesByType[rule.type]) {
                rulesByType[rule.type] = [];
            }
            rulesByType[rule.type].push(rule);
        });
        
        // 详情日志
        let details = '<div class="detail-section">合并详情日志�?br>';
        details += '============<br>';
        details += `原始规则数量�?{originalRulesCount}<br>`;
        details += `忽略的行数（空行、注释等）：${ignoredLinesList.length}<br>`;
        details += `有效规则数量�?{allParsedRules.length}<br>`;
        details += '============</div><br>';

        // 处理域名规则
        details += '<div class="detail-section">域名规则处理�?br>';
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
            
            // 将唯一的DOMAIN规则添加到结�?
            Object.values(uniqueDomains).forEach(rule => mergedRulesList.push(rule));
            
            details += `DOMAIN规则处理完成，原�? ${rulesByType['DOMAIN'].length}，唯一: ${Object.keys(uniqueDomains).length}，删除重�? ${duplicateCount}<br>`;
        }
        
        // 处理DOMAIN-SUFFIX规则
        if (rulesByType['DOMAIN-SUFFIX']) {
            details += `<br>发现${rulesByType['DOMAIN-SUFFIX'].length}条DOMAIN-SUFFIX规则<br>`;
            
            // 去重并检查DOMAIN-SUFFIX之间的关�?
            const suffixRules = [...rulesByType['DOMAIN-SUFFIX']];
            const uniqueSuffixes = [];
            const skippedSuffixes = new Set();
            let containedCount = 0;
            
            // 第一步：排除那些被其他后缀包含的规�?
            for (let i = 0; i < suffixRules.length; i++) {
                if (skippedSuffixes.has(i)) continue;
                
                const rule1 = suffixRules[i];
                let isContained = false;
                
                for (let j = 0; j < suffixRules.length; j++) {
                    if (i === j || skippedSuffixes.has(j)) continue;
                    
                    const rule2 = suffixRules[j];
                    // 如果策略不同，不能合�?
                    if (rule1.policy !== rule2.policy) continue;
                    
                    const relationship = domainRelationship(rule1.value, rule2.value);
                    
                    if (relationship === 'SUBDOMAIN') {
                        isContained = true;
                        details += `合并: 域名后缀 ${rule1.value} �?${rule2.value} 包含，保�?${rule2.value}<br>`;
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
            
            // 将唯一的DOMAIN-SUFFIX规则添加到结�?
            uniqueSuffixes.forEach(rule => mergedRulesList.push(rule));
            
            details += `DOMAIN-SUFFIX规则处理完成，原�? ${suffixRules.length}，唯一: ${uniqueSuffixes.length}，删除包含关�? ${containedCount}<br>`;
        }
    } 
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
            
            // 将唯一的DOMAIN-KEYWORD规则添加到结�?
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
                            details += `DOMAIN-KEYWORD: ${keywordRule.value} 已被 DOMAIN-SUFFIX: ${suffixRule.value} 包含，删�?br>`;
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
            
            // 更新合并的规则列�?
            // 先移除所有DOMAIN-KEYWORD规则
            const nonKeywordRules = mergedRulesList.filter(rule => rule.type !== 'DOMAIN-KEYWORD');
            mergedRulesList.length = 0;
            // 然后添加保留的DOMAIN-KEYWORD规则和其他规�?
            mergedRulesList.push(...finalKeywordRules);
            mergedRulesList.push(...nonKeywordRules);
            
            details += `DOMAIN-KEYWORD规则处理完成，原�? ${rulesByType['DOMAIN-KEYWORD'].length}，去重后: ${keywordRules.length}，最终保�? ${finalKeywordRules.length}，移除重�? ${duplicateCount}，移除冗�? ${containedCount}<br>`;
        }
        
        // 处理DOMAIN和DOMAIN-SUFFIX之间的关�?
        if (rulesByType['DOMAIN'] && rulesByType['DOMAIN-SUFFIX']) {
            details += '<br>检查DOMAIN与DOMAIN-SUFFIX之间的关�?br>';
            
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
                            details += `DOMAIN: ${domainRule.value} 已被 DOMAIN-SUFFIX: ${suffixRule.value} 包含，删�?br>`;
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
            
            // 更新合并的规则列�?
            const otherRulesExceptDomain = mergedRulesList.filter(rule => rule.type !== 'DOMAIN');
            mergedRulesList.length = 0;
            mergedRulesList.push(...domainsToKeep);
            mergedRulesList.push(...otherRulesExceptDomain);
            
            details += `DOMAIN与DOMAIN-SUFFIX关系处理完成，移除被包含的DOMAIN规则: ${containedCount}<br>`;
        }
        
        details += '</div>';
        
        // 处理IP规则
        details += '<div class="detail-section">IP规则处理�?br>';
        details += '------------<br>'; 
        // 处理IP-CIDR规则
        if (rulesByType['IP-CIDR']) {
            details += `<br>发现${rulesByType['IP-CIDR'].length}条IP-CIDR规则<br>`;
            
            const cidrRules = [...rulesByType['IP-CIDR']];
            const mergedCidrRules = [];
            
            // 对同一策略的CIDR进行排序和合�?
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
                
                // 第一步：去除被其他CIDR完全包含的子�?
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
                                details += `合并: IP-CIDR ${rule1.value} �?${rule2.value} 包含，保�?${rule2.value}<br>`;
                                details += `移除: <span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule1))}">${rule1.original}</span><br>`;
                                removedRulesList.push(rule1);
                                processedCidrs.add(i);
                                break;
                            }
                        } catch (e) {
                            details += `错误: 处理IP-CIDR时出�?${e.message}<br>`;
                        }
                    }
                    
                    if (!isContained) {
                        mergedCidrRules.push(rule1);
                    }
                }
                
                // 第二步：尝试合并相邻的CIDR
                let hasMerged = true;
                let currentCidrs = [...mergedCidrRules.filter(r => r.policy === policy)];
                let iterationCount = 0; // 记录迭代次数，以防无限循�?
                
                while (hasMerged && currentCidrs.length > 1 && iterationCount < 10) {
                    iterationCount++;
                    hasMerged = false;
                    
                    const nextCidrs = [];
                    const processed = new Set();
                    
                    details += `<br>合并CIDR迭代 #${iterationCount}, 当前规则�? ${currentCidrs.length}<br>`;
                    
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
                                    
                                    // 标记这两条规则被合并�?
                                    details += `移除: <span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule1))}">${rule1.original}</span><br>`;
                                    details += `移除: <span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule2))}">${rule2.original}</span><br>`;
                                    
                                    if (!removedRulesList.includes(rule1)) removedRulesList.push(rule1);
                                    if (!removedRulesList.includes(rule2)) removedRulesList.push(rule2);
                                    break;
                                }
                            } catch (e) {
                                details += `错误: 合并IP-CIDR时出�?${e.message}<br>`;
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
            
            // 将合并后的IP-CIDR规则添加到结�?
            mergedRulesList.push(...mergedCidrRules);
            
            details += `<br>IP-CIDR规则处理完成，原始规�? ${cidrRules.length}，合并后: ${mergedCidrRules.length}，移�? ${cidrRules.length - mergedCidrRules.length}<br>`;
        }
        
        details += '</div>';
        
        // 处理其他类型的规�?
        const processedTypes = ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR'];
        const otherRules = allParsedRules.filter(rule => !processedTypes.includes(rule.type));
        
        if (otherRules.length > 0) {
            details += '<div class="detail-section">其他类型规则处理�?br>';
            details += '----------------<br>';
            details += `发现${otherRules.length}条其他类型规则，进行简单去�?br>`;
            
            // 简单去�?
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
            
            // 将其他类型的规则添加到结�?
            Object.values(uniqueOtherRules).forEach(rule => mergedRulesList.push(rule));
            
            details += `其他规则处理完成，原�? ${otherRules.length}，唯一: ${Object.keys(uniqueOtherRules).length}，删除重�? ${duplicateCount}<br>`;
            details += '</div>';
        } 
        // 统计结果
        details += '<div class="detail-section">';
        details += '<br>=========<br>';
        details += `合并后规则数�? ${mergedRulesList.length}<br>`;
        details += `删除的重复或冗余规则数量: ${removedRulesList.length}<br>`;
        details += `忽略的行�? ${ignoredLinesList.length}<br>`;
        
        // 计算总数核对
        const totalAccounted = mergedRulesList.length + removedRulesList.length + ignoredLinesList.length;
        details += `总计�? ${totalAccounted} / ${originalRulesCount}<br>`;
        
        if (totalAccounted !== originalRulesCount) {
            details += `警告: 计数不一致，差异: ${originalRulesCount - totalAccounted}<br>`;
        }
        
        details += '=========<br>';
        details += '</div>';

        // 排序规则
        sortRules();
        
        // 更新输出
        updateOutputDisplay();
        
        // 更新UI - 详情显示
        detailOutput.innerHTML = details;
        
        // 更新统计
        updateStats();
        
        // 添加点击事件监听器以恢复规则
        const removedRuleElements = document.querySelectorAll('.removed-rule');
        removedRuleElements.forEach(element => {
            element.addEventListener('click', function() {
                const ruleData = JSON.parse(decodeURIComponent(this.getAttribute('data-rule')));
                restoreRule(ruleData);
            });
        });
    }

    // 复制到剪贴板
    function copyToClipboard(text) {
        if (navigator.clipboard && window.isSecureContext) {
            // 使用现代Clipboard API
            navigator.clipboard.writeText(text)
                .then(() => {
                    alert('已复制到剪贴�?);
                })
                .catch(err => {
                    console.error('复制失败:', err);
                    // 回退到传统方�?
                    fallbackCopyToClipboard(text);
                });
        } else {
            // 使用传统方法
            fallbackCopyToClipboard(text);
        }
    }
    
    // 传统剪贴板复制方�?
    function fallbackCopyToClipboard(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        
        try {
            document.execCommand('copy');
            alert('已复制到剪贴�?);
        } catch (err) {
            console.error('复制失败:', err);
            alert('复制失败，请手动复制');
        }
        
        document.body.removeChild(textArea);
    }

    // 下载规则文件
    function downloadRules() {
        if (!outputRules.value.trim()) {
            alert('没有规则可下�?);
            return;
        }
        
        // 处理规则文本，移除行�?
        const lines = outputRules.value.split('\n');
        const cleanedLines = lines.map(line => {
            // 移除每行开头的行号 "123. "
            const lineNumMatch = line.match(/^\d+\.\s(.*)/);
            if (lineNumMatch) {
                return lineNumMatch[1];
            }
            return line;
        });
        
        const cleanedText = cleanedLines.join('\n');
        
        const blob = new Blob([cleanedText], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'surge_rules_merged.conf';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // 清空输入
    function clearInputs() {
        inputRules.value = '';
        outputRules.value = '';
        detailOutput.innerHTML = '';
        originalCount.textContent = '原始规则数量: 0';
        mergedCount.textContent = '合并后规则数�? 0';
        removedCount.textContent = '移除重复/重叠规则数量: 0';
        updateLineNumbers(); // 更新行号
    }

    // 加载示例
    function loadExample() {
        inputRules.value = `# 域名规则示例 - 测试重复和重叠规�?
# 重复的DOMAIN规则
DOMAIN,www.apple.com,Proxy
DOMAIN,www.apple.com,Proxy
DOMAIN,developer.apple.com,Proxy
DOMAIN,www.google.com,Proxy
DOMAIN,store.apple.com,Proxy
DOMAIN,maps.google.com,Proxy

# 这些DOMAIN规则将被DOMAIN-SUFFIX覆盖
DOMAIN,mail.google.com,Proxy
DOMAIN,drive.google.com,Proxy
DOMAIN,docs.google.com,Proxy
DOMAIN,cloud.apple.com,Proxy
DOMAIN,support.apple.com,Proxy

# DOMAIN-SUFFIX规则
DOMAIN-SUFFIX,apple.com,Proxy  # 将覆盖上面的apple.com域名
DOMAIN-SUFFIX,icloud.com,Proxy
DOMAIN-SUFFIX,google.com,Proxy  # 将覆盖上面的google.com域名
DOMAIN-SUFFIX,github.com,Proxy
DOMAIN-SUFFIX,microsoft.com,Proxy
DOMAIN-SUFFIX,windows.com,Proxy

# 重叠的DOMAIN-SUFFIX测试
DOMAIN-SUFFIX,cdn.apple.com,Proxy  # 将被apple.com覆盖
DOMAIN-SUFFIX,store.apple.com,Proxy  # 将被apple.com覆盖
DOMAIN-SUFFIX,mail.google.com,Proxy  # 将被google.com覆盖

# DOMAIN-KEYWORD规则
DOMAIN-KEYWORD,google,Proxy  # 可能冗余，因为已有google.com
DOMAIN-KEYWORD,apple,Proxy   # 可能冗余，因为已有apple.com
DOMAIN-KEYWORD,github,Proxy  # 可能冗余，因为已有github.com
DOMAIN-KEYWORD,steam,Proxy
DOMAIN-KEYWORD,epic,Proxy

# IP-CIDR规则 - 测试包含关系和相邻网段合�?
IP-CIDR,192.168.0.0/16,DIRECT  # 更大的网�?
IP-CIDR,192.168.1.0/24,DIRECT  # 被上面的网段包含
IP-CIDR,192.168.2.0/24,DIRECT  # 被上面的网段包含
IP-CIDR,10.0.0.0/8,DIRECT     # 更大的网�?
IP-CIDR,10.0.0.0/16,DIRECT    # 被上面的网段包含
IP-CIDR,10.1.0.0/16,DIRECT    # 被上面的网段包含
IP-CIDR,172.16.0.0/12,DIRECT
IP-CIDR,127.0.0.0/8,DIRECT

# 可合并的相邻网段
IP-CIDR,172.20.0.0/16,DIRECT
IP-CIDR,172.21.0.0/16,DIRECT  # 可与上面的合并为172.20.0.0/15

# 其他规则
URL-REGEX,^http://google\\.com,Proxy
URL-REGEX,^http://google\\.com,Proxy  # 重复规则
USER-AGENT,Instagram*,DIRECT
PROCESS-NAME,Telegram,Proxy
PROCESS-NAME,Chrome,Proxy

# 空行和注释行测试



# 这是一个注释行
`;
        updateLineNumbers(); // 更新行号
    }
}); 
document.addEventListener('DOMContentLoaded', function() {
    // 获取DOM元素
    const inputRules = document.getElementById('input-rules');
    const outputRules = document.getElementById('output-rules');
    const detailOutput = document.getElementById('detail-output');
    const inputLineNumbers = document.getElementById('input-line-numbers');
    const mergeBtn = document.getElementById('merge-btn');
    const clearBtn = document.getElementById('clear-btn');
    const exampleBtn = document.getElementById('example-btn');
    const copyBtn = document.getElementById('copy-btn');
    const downloadBtn = document.getElementById('download-btn');
    const copyDetailBtn = document.getElementById('copy-detail-btn');
    const clearDetailBtn = document.getElementById('clear-detail-btn');
    const originalCount = document.getElementById('original-count');
    const mergedCount = document.getElementById('merged-count');
    const removedCount = document.getElementById('removed-count');
    const sortMethod = document.getElementById('sort-method');
    const applySort = document.getElementById('apply-sort');
    
    // 存储所有规�?
    let allParsedRules = [];
    let mergedRulesList = [];
    let removedRulesList = [];
    let ignoredLinesList = [];

    // 初始化行号显�?
    updateLineNumbers();

    // 监听输入变化以更新行�?
    inputRules.addEventListener('input', updateLineNumbers);
    inputRules.addEventListener('scroll', syncScroll);
    
    // 绑定排序按钮
    applySort.addEventListener('click', function() {
        if (mergedRulesList.length > 0) {
            sortRules();
            updateOutputDisplay();
        }
    });

    // 同步滚动
    function syncScroll() {
        inputLineNumbers.scrollTop = inputRules.scrollTop;
    }

    // 更新行号显示
    function updateLineNumbers() {
        const lines = inputRules.value.split('\n');
        let lineNumbersHtml = '';
        
        for (let i = 0; i < lines.length; i++) {
            lineNumbersHtml += `<div>${i + 1}</div>`;
        }
        
        // 确保至少有一�?
        if (lines.length === 0 || (lines.length === 1 && lines[0] === '')) {
            lineNumbersHtml = '<div>1</div>';
        }
        
        inputLineNumbers.innerHTML = lineNumbersHtml;
        
        // 调整行号区域的高度以匹配文本区域
        inputLineNumbers.style.height = `${inputRules.scrollHeight}px`;
    }

    // 绑定按钮事件
    mergeBtn.addEventListener('click', mergeRules);
    clearBtn.addEventListener('click', clearInputs);
    exampleBtn.addEventListener('click', loadExample);
    copyBtn.addEventListener('click', () => copyToClipboard(outputRules.value));
    downloadBtn.addEventListener('click', downloadRules);
    copyDetailBtn.addEventListener('click', () => copyToClipboard(detailOutput.innerText));
    clearDetailBtn.addEventListener('click', () => {
        detailOutput.innerHTML = '';
    });
}); 
    // CIDR操作工具
    const ipCidrTools = {
        // 将IP转换为整�?
        ipToInt: function(ip) {
            return ip.split('.')
                .reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
        },

        // 将整数转换回IP
        intToIp: function(int) {
            return [
                (int >>> 24) & 255,
                (int >>> 16) & 255,
                (int >>> 8) & 255,
                int & 255
            ].join('.');
        },

        // 计算CIDR中的掩码
        getCidrMask: function(bits) {
            return ~(Math.pow(2, 32 - bits) - 1) >>> 0;
        },

        // 获取CIDR的第一个IP
        getCidrFirstIp: function(cidr) {
            const [ip, bits] = cidr.split('/');
            const mask = this.getCidrMask(parseInt(bits, 10));
            return this.intToIp(this.ipToInt(ip) & mask);
        },

        // 获取CIDR的最后一个IP
        getCidrLastIp: function(cidr) {
            const [ip, bits] = cidr.split('/');
            const mask = this.getCidrMask(parseInt(bits, 10));
            const invMask = ~mask >>> 0;
            return this.intToIp((this.ipToInt(ip) & mask) | invMask);
        },

        // 检查一个CIDR是否完全包含另一个CIDR
        cidrContains: function(cidr1, cidr2) {
            const [ip1, bits1] = cidr1.split('/');
            const [ip2, bits2] = cidr2.split('/');
            
            const mask1 = this.getCidrMask(parseInt(bits1, 10));
            const ipInt1 = this.ipToInt(ip1) & mask1;
            const ipInt2 = this.ipToInt(ip2);
            
            // 如果掩码2比掩�?小，则不可能包含
            if (parseInt(bits1, 10) > parseInt(bits2, 10)) {
                return false;
            }
            
            // 检查ip2是否在cidr1范围�?
            return (ipInt2 & mask1) === ipInt1;
        },

        // 尝试合并两个CIDR
        canMergeCidrs: function(cidr1, cidr2) {
            const [ip1, bits1] = cidr1.split('/');
            const [ip2, bits2] = cidr2.split('/');
            
            // 如果掩码不同，无法简单合�?
            if (bits1 !== bits2) {
                return false;
            }
            
            const ipInt1 = this.ipToInt(ip1);
            const ipInt2 = this.ipToInt(ip2);
            const bits = parseInt(bits1, 10);
            const mask = this.getCidrMask(bits);
            
            // 检查如果减�?位掩码，两个网络是否会合并成一�?
            const parentMask = this.getCidrMask(bits - 1);
            return (ipInt1 & parentMask) === (ipInt2 & parentMask);
        },
        
        // 合并两个可合并的CIDR
        mergeCidrs: function(cidr1, cidr2) {
            if (!this.canMergeCidrs(cidr1, cidr2)) {
                return null;
            }
            
            const [ip1, bits1] = cidr1.split('/');
            const bits = parseInt(bits1, 10);
            const parentMask = this.getCidrMask(bits - 1);
            
            return this.intToIp(this.ipToInt(ip1) & parentMask) + '/' + (bits - 1);
        }
    };

    // 规则解析和处理函�?
    function parseRule(rule) {
        // 移除注释
        const commentIndex = rule.indexOf('#');
        if (commentIndex !== -1) {
            rule = rule.substring(0, commentIndex).trim();
        }
        
        // 如果为空行则跳过
        if (!rule) {
            return null;
        }
        
        // 分割规则组成部分
        const parts = rule.split(',');
        if (parts.length < 2) {
            // 规则格式不正�?
            return { type: 'UNKNOWN', original: rule };
        }
        
        const type = parts[0];
        const value = parts[1];
        const policy = parts.length > 2 ? parts.slice(2).join(',') : '';
        
        return { type, value, policy, original: rule };
    }

    // 检查域名是否包含或被包�?
    function domainRelationship(domain1, domain2) {
        // 如果完全相同
        if (domain1 === domain2) {
            return 'SAME';
        }
        
        // 检查后缀关系
        if (domain1.endsWith('.' + domain2)) {
            return 'SUBDOMAIN'; // domain1是domain2的子域名
        }
        
        if (domain2.endsWith('.' + domain1)) {
            return 'PARENT'; // domain1是domain2的父域名
        }
        
        return 'UNRELATED';
    } 
    // 恢复被删除的规则
    function restoreRule(rule) {
        // 从已删除列表中移�?
        const index = removedRulesList.findIndex(r => r.original === rule.original);
        if (index !== -1) {
            removedRulesList.splice(index, 1);
        }
        
        // 添加到合并列�?
        mergedRulesList.push(rule);
        
        // 更新统计和显�?
        updateStats();
        sortRules();
        updateOutputDisplay();
        
        // 更新详情显示
        const details = detailOutput.innerHTML;
        detailOutput.innerHTML = details.replace(
            `<span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule))}">${rule.original}</span>`,
            `<span>${rule.original}</span> (已恢�?`
        );
    }
    
    // 排序规则
    function sortRules() {
        const method = sortMethod.value;
        
        if (method === 'none') {
            return; // 不排�?
        }
        
        // 按类型分�?
        const grouped = {};
        mergedRulesList.forEach(rule => {
            if (!grouped[rule.type]) {
                grouped[rule.type] = [];
            }
            grouped[rule.type].push(rule);
        });
        
        // 对每种规则类型应用排�?
        for (const type in grouped) {
            if (type === 'IP-CIDR' || type === 'IP-CIDR6') {
                if (method === 'ip') {
                    // IP按数字大小排�?
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
                    // 按字母排�?
                    grouped[type].sort((a, b) => a.value.localeCompare(b.value));
                }
            } else if (type.startsWith('DOMAIN')) {
                if (method === 'domain') {
                    // 按域名主体分组排�?
                    grouped[type].sort((a, b) => {
                        // 提取域名的主要部分（例如 apple.com, google.com�?
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
                    // 按字母排�?
                    grouped[type].sort((a, b) => a.value.localeCompare(b.value));
                }
            } else {
                // 其他规则类型按字母排�?
                if (method === 'alpha' || method === 'domain') {
                    grouped[type].sort((a, b) => a.value.localeCompare(b.value));
                }
            }
        }
        
        // 重建合并规则列表
        mergedRulesList = [];
        
        // 按顺序添加各类规�?
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
        // 转换回文本格�?
        let resultText = '';
        
        if (mergedRulesList.length > 0) {
            const grouped = {};
            
            // 按类型分�?
            mergedRulesList.forEach(rule => {
                if (!grouped[rule.type]) {
                    grouped[rule.type] = [];
                }
                grouped[rule.type].push(rule);
            });
            
            // 添加行号计数�?
            let lineNumber = 1;
            
            // 按顺序输出域名规�?
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
        mergedCount.textContent = `合并后规则数�? ${mergedRulesList.length}`;
        removedCount.textContent = `移除重复/重叠规则数量: ${removedRulesList.length}`;
    } 
    // 合并规则
    function mergeRules() {
        const input = inputRules.value.trim();
        if (!input) {
            alert('请输入规�?);
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
        
        // 解析所有规�?
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
        
        // 按类型分组规�?
        const rulesByType = {};
        allParsedRules.forEach(rule => {
            if (!rulesByType[rule.type]) {
                rulesByType[rule.type] = [];
            }
            rulesByType[rule.type].push(rule);
        });
        
        // 详情日志
        let details = '<div class="detail-section">合并详情日志�?br>';
        details += '============<br>';
        details += `原始规则数量�?{originalRulesCount}<br>`;
        details += `忽略的行数（空行、注释等）：${ignoredLinesList.length}<br>`;
        details += `有效规则数量�?{allParsedRules.length}<br>`;
        details += '============</div><br>';

        // 处理域名规则
        details += '<div class="detail-section">域名规则处理�?br>';
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
            
            // 将唯一的DOMAIN规则添加到结�?
            Object.values(uniqueDomains).forEach(rule => mergedRulesList.push(rule));
            
            details += `DOMAIN规则处理完成，原�? ${rulesByType['DOMAIN'].length}，唯一: ${Object.keys(uniqueDomains).length}，删除重�? ${duplicateCount}<br>`;
        }
        
        // 处理DOMAIN-SUFFIX规则
        if (rulesByType['DOMAIN-SUFFIX']) {
            details += `<br>发现${rulesByType['DOMAIN-SUFFIX'].length}条DOMAIN-SUFFIX规则<br>`;
            
            // 去重并检查DOMAIN-SUFFIX之间的关�?
            const suffixRules = [...rulesByType['DOMAIN-SUFFIX']];
            const uniqueSuffixes = [];
            const skippedSuffixes = new Set();
            let containedCount = 0;
            
            // 第一步：排除那些被其他后缀包含的规�?
            for (let i = 0; i < suffixRules.length; i++) {
                if (skippedSuffixes.has(i)) continue;
                
                const rule1 = suffixRules[i];
                let isContained = false;
                
                for (let j = 0; j < suffixRules.length; j++) {
                    if (i === j || skippedSuffixes.has(j)) continue;
                    
                    const rule2 = suffixRules[j];
                    // 如果策略不同，不能合�?
                    if (rule1.policy !== rule2.policy) continue;
                    
                    const relationship = domainRelationship(rule1.value, rule2.value);
                    
                    if (relationship === 'SUBDOMAIN') {
                        isContained = true;
                        details += `合并: 域名后缀 ${rule1.value} �?${rule2.value} 包含，保�?${rule2.value}<br>`;
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
            
            // 将唯一的DOMAIN-SUFFIX规则添加到结�?
            uniqueSuffixes.forEach(rule => mergedRulesList.push(rule));
            
            details += `DOMAIN-SUFFIX规则处理完成，原�? ${suffixRules.length}，唯一: ${uniqueSuffixes.length}，删除包含关�? ${containedCount}<br>`;
        }
    } 
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
            
            // 将唯一的DOMAIN-KEYWORD规则添加到结�?
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
                            details += `DOMAIN-KEYWORD: ${keywordRule.value} 已被 DOMAIN-SUFFIX: ${suffixRule.value} 包含，删�?br>`;
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
            
            // 更新合并的规则列�?
            // 先移除所有DOMAIN-KEYWORD规则
            const nonKeywordRules = mergedRulesList.filter(rule => rule.type !== 'DOMAIN-KEYWORD');
            mergedRulesList.length = 0;
            // 然后添加保留的DOMAIN-KEYWORD规则和其他规�?
            mergedRulesList.push(...finalKeywordRules);
            mergedRulesList.push(...nonKeywordRules);
            
            details += `DOMAIN-KEYWORD规则处理完成，原�? ${rulesByType['DOMAIN-KEYWORD'].length}，去重后: ${keywordRules.length}，最终保�? ${finalKeywordRules.length}，移除重�? ${duplicateCount}，移除冗�? ${containedCount}<br>`;
        }
        
        // 处理DOMAIN和DOMAIN-SUFFIX之间的关�?
        if (rulesByType['DOMAIN'] && rulesByType['DOMAIN-SUFFIX']) {
            details += '<br>检查DOMAIN与DOMAIN-SUFFIX之间的关�?br>';
            
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
                            details += `DOMAIN: ${domainRule.value} 已被 DOMAIN-SUFFIX: ${suffixRule.value} 包含，删�?br>`;
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
            
            // 更新合并的规则列�?
            const otherRulesExceptDomain = mergedRulesList.filter(rule => rule.type !== 'DOMAIN');
            mergedRulesList.length = 0;
            mergedRulesList.push(...domainsToKeep);
            mergedRulesList.push(...otherRulesExceptDomain);
            
            details += `DOMAIN与DOMAIN-SUFFIX关系处理完成，移除被包含的DOMAIN规则: ${containedCount}<br>`;
        }
        
        details += '</div>';
        
        // 处理IP规则
        details += '<div class="detail-section">IP规则处理�?br>';
        details += '------------<br>'; 
        // 处理IP-CIDR规则
        if (rulesByType['IP-CIDR']) {
            details += `<br>发现${rulesByType['IP-CIDR'].length}条IP-CIDR规则<br>`;
            
            const cidrRules = [...rulesByType['IP-CIDR']];
            const mergedCidrRules = [];
            
            // 对同一策略的CIDR进行排序和合�?
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
                
                // 第一步：去除被其他CIDR完全包含的子�?
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
                                details += `合并: IP-CIDR ${rule1.value} �?${rule2.value} 包含，保�?${rule2.value}<br>`;
                                details += `移除: <span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule1))}">${rule1.original}</span><br>`;
                                removedRulesList.push(rule1);
                                processedCidrs.add(i);
                                break;
                            }
                        } catch (e) {
                            details += `错误: 处理IP-CIDR时出�?${e.message}<br>`;
                        }
                    }
                    
                    if (!isContained) {
                        mergedCidrRules.push(rule1);
                    }
                }
                
                // 第二步：尝试合并相邻的CIDR
                let hasMerged = true;
                let currentCidrs = [...mergedCidrRules.filter(r => r.policy === policy)];
                let iterationCount = 0; // 记录迭代次数，以防无限循�?
                
                while (hasMerged && currentCidrs.length > 1 && iterationCount < 10) {
                    iterationCount++;
                    hasMerged = false;
                    
                    const nextCidrs = [];
                    const processed = new Set();
                    
                    details += `<br>合并CIDR迭代 #${iterationCount}, 当前规则�? ${currentCidrs.length}<br>`;
                    
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
                                    
                                    // 标记这两条规则被合并�?
                                    details += `移除: <span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule1))}">${rule1.original}</span><br>`;
                                    details += `移除: <span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule2))}">${rule2.original}</span><br>`;
                                    
                                    if (!removedRulesList.includes(rule1)) removedRulesList.push(rule1);
                                    if (!removedRulesList.includes(rule2)) removedRulesList.push(rule2);
                                    break;
                                }
                            } catch (e) {
                                details += `错误: 合并IP-CIDR时出�?${e.message}<br>`;
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
            
            // 将合并后的IP-CIDR规则添加到结�?
            mergedRulesList.push(...mergedCidrRules);
            
            details += `<br>IP-CIDR规则处理完成，原始规�? ${cidrRules.length}，合并后: ${mergedCidrRules.length}，移�? ${cidrRules.length - mergedCidrRules.length}<br>`;
        }
        
        details += '</div>';
        
        // 处理其他类型的规�?
        const processedTypes = ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR'];
        const otherRules = allParsedRules.filter(rule => !processedTypes.includes(rule.type));
        
        if (otherRules.length > 0) {
            details += '<div class="detail-section">其他类型规则处理�?br>';
            details += '----------------<br>';
            details += `发现${otherRules.length}条其他类型规则，进行简单去�?br>`;
            
            // 简单去�?
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
            
            // 将其他类型的规则添加到结�?
            Object.values(uniqueOtherRules).forEach(rule => mergedRulesList.push(rule));
            
            details += `其他规则处理完成，原�? ${otherRules.length}，唯一: ${Object.keys(uniqueOtherRules).length}，删除重�? ${duplicateCount}<br>`;
            details += '</div>';
        } 
        // 统计结果
        details += '<div class="detail-section">';
        details += '<br>=========<br>';
        details += `合并后规则数�? ${mergedRulesList.length}<br>`;
        details += `删除的重复或冗余规则数量: ${removedRulesList.length}<br>`;
        details += `忽略的行�? ${ignoredLinesList.length}<br>`;
        
        // 计算总数核对
        const totalAccounted = mergedRulesList.length + removedRulesList.length + ignoredLinesList.length;
        details += `总计�? ${totalAccounted} / ${originalRulesCount}<br>`;
        
        if (totalAccounted !== originalRulesCount) {
            details += `警告: 计数不一致，差异: ${originalRulesCount - totalAccounted}<br>`;
        }
        
        details += '=========<br>';
        details += '</div>';

        // 排序规则
        sortRules();
        
        // 更新输出
        updateOutputDisplay();
        
        // 更新UI - 详情显示
        detailOutput.innerHTML = details;
        
        // 更新统计
        updateStats();
        
        // 添加点击事件监听器以恢复规则
        const removedRuleElements = document.querySelectorAll('.removed-rule');
        removedRuleElements.forEach(element => {
            element.addEventListener('click', function() {
                const ruleData = JSON.parse(decodeURIComponent(this.getAttribute('data-rule')));
                restoreRule(ruleData);
            });
        });
    }

    // 复制到剪贴板
    function copyToClipboard(text) {
        if (navigator.clipboard && window.isSecureContext) {
            // 使用现代Clipboard API
            navigator.clipboard.writeText(text)
                .then(() => {
                    alert('已复制到剪贴�?);
                })
                .catch(err => {
                    console.error('复制失败:', err);
                    // 回退到传统方�?
                    fallbackCopyToClipboard(text);
                });
        } else {
            // 使用传统方法
            fallbackCopyToClipboard(text);
        }
    }
    
    // 传统剪贴板复制方�?
    function fallbackCopyToClipboard(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        
        try {
            document.execCommand('copy');
            alert('已复制到剪贴�?);
        } catch (err) {
            console.error('复制失败:', err);
            alert('复制失败，请手动复制');
        }
        
        document.body.removeChild(textArea);
    }

    // 下载规则文件
    function downloadRules() {
        if (!outputRules.value.trim()) {
            alert('没有规则可下�?);
            return;
        }
        
        // 处理规则文本，移除行�?
        const lines = outputRules.value.split('\n');
        const cleanedLines = lines.map(line => {
            // 移除每行开头的行号 "123. "
            const lineNumMatch = line.match(/^\d+\.\s(.*)/);
            if (lineNumMatch) {
                return lineNumMatch[1];
            }
            return line;
        });
        
        const cleanedText = cleanedLines.join('\n');
        
        const blob = new Blob([cleanedText], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'surge_rules_merged.conf';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // 清空输入
    function clearInputs() {
        inputRules.value = '';
        outputRules.value = '';
        detailOutput.innerHTML = '';
        originalCount.textContent = '原始规则数量: 0';
        mergedCount.textContent = '合并后规则数�? 0';
        removedCount.textContent = '移除重复/重叠规则数量: 0';
        updateLineNumbers(); // 更新行号
    }

    // 加载示例
    function loadExample() {
        inputRules.value = `# 域名规则示例 - 测试重复和重叠规�?
# 重复的DOMAIN规则
DOMAIN,www.apple.com,Proxy
DOMAIN,www.apple.com,Proxy
DOMAIN,developer.apple.com,Proxy
DOMAIN,www.google.com,Proxy
DOMAIN,store.apple.com,Proxy
DOMAIN,maps.google.com,Proxy

# 这些DOMAIN规则将被DOMAIN-SUFFIX覆盖
DOMAIN,mail.google.com,Proxy
DOMAIN,drive.google.com,Proxy
DOMAIN,docs.google.com,Proxy
DOMAIN,cloud.apple.com,Proxy
DOMAIN,support.apple.com,Proxy

# DOMAIN-SUFFIX规则
DOMAIN-SUFFIX,apple.com,Proxy  # 将覆盖上面的apple.com域名
DOMAIN-SUFFIX,icloud.com,Proxy
DOMAIN-SUFFIX,google.com,Proxy  # 将覆盖上面的google.com域名
DOMAIN-SUFFIX,github.com,Proxy
DOMAIN-SUFFIX,microsoft.com,Proxy
DOMAIN-SUFFIX,windows.com,Proxy

# 重叠的DOMAIN-SUFFIX测试
DOMAIN-SUFFIX,cdn.apple.com,Proxy  # 将被apple.com覆盖
DOMAIN-SUFFIX,store.apple.com,Proxy  # 将被apple.com覆盖
DOMAIN-SUFFIX,mail.google.com,Proxy  # 将被google.com覆盖

# DOMAIN-KEYWORD规则
DOMAIN-KEYWORD,google,Proxy  # 可能冗余，因为已有google.com
DOMAIN-KEYWORD,apple,Proxy   # 可能冗余，因为已有apple.com
DOMAIN-KEYWORD,github,Proxy  # 可能冗余，因为已有github.com
DOMAIN-KEYWORD,steam,Proxy
DOMAIN-KEYWORD,epic,Proxy

# IP-CIDR规则 - 测试包含关系和相邻网段合�?
IP-CIDR,192.168.0.0/16,DIRECT  # 更大的网�?
IP-CIDR,192.168.1.0/24,DIRECT  # 被上面的网段包含
IP-CIDR,192.168.2.0/24,DIRECT  # 被上面的网段包含
IP-CIDR,10.0.0.0/8,DIRECT     # 更大的网�?
IP-CIDR,10.0.0.0/16,DIRECT    # 被上面的网段包含
IP-CIDR,10.1.0.0/16,DIRECT    # 被上面的网段包含
IP-CIDR,172.16.0.0/12,DIRECT
IP-CIDR,127.0.0.0/8,DIRECT

# 可合并的相邻网段
IP-CIDR,172.20.0.0/16,DIRECT
IP-CIDR,172.21.0.0/16,DIRECT  # 可与上面的合并为172.20.0.0/15

# 其他规则
URL-REGEX,^http://google\\.com,Proxy
URL-REGEX,^http://google\\.com,Proxy  # 重复规则
USER-AGENT,Instagram*,DIRECT
PROCESS-NAME,Telegram,Proxy
PROCESS-NAME,Chrome,Proxy

# 空行和注释行测试



# 这是一个注释行
`;
        updateLineNumbers(); // 更新行号
    }
}); 
