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
    
    // 存储所有规则
    let allParsedRules = [];
    let mergedRulesList = [];
    let removedRulesList = [];
    let ignoredLinesList = [];

    // 存储所有规则的重复项映射
    let duplicateRulesMap = {};
    // 存储当前查看的重复项索引
    let currentDuplicateIndices = {};

    // 初始化行号显示
    updateLineNumbers();

    // 监听输入变化以更新行号
    inputRules.addEventListener('input', updateLineNumbers);
    inputRules.addEventListener('scroll', syncScroll);
    
    // 监听输出文本区域滚动
    outputRules.addEventListener('scroll', function() {
        const outputLineNumbers = document.getElementById('output-line-numbers');
        if (outputLineNumbers) {
            outputLineNumbers.scrollTop = this.scrollTop;
        }
    });
    
    // 监听窗口大小变化，自动调整行号区域
    window.addEventListener('resize', updateLineNumbers);
    
    // 绑定排序按钮
    applySort.addEventListener('click', function() {
        if (mergedRulesList.length > 0) {
            sortRules();
            updateOutputDisplay();
        }
    });

    // CIDR操作工具
    const ipCidrTools = {
        // 将IP转换为整数
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
            
            // 如果掩码2比掩码1小，则不可能包含
            if (parseInt(bits1, 10) > parseInt(bits2, 10)) {
                return false;
            }
            
            // 检查ip2是否在cidr1范围内
            return (ipInt2 & mask1) === ipInt1;
        },

        // 尝试合并两个CIDR
        canMergeCidrs: function(cidr1, cidr2) {
            const [ip1, bits1] = cidr1.split('/');
            const [ip2, bits2] = cidr2.split('/');
            
            // 如果掩码不同，无法简单合并
            if (bits1 !== bits2) {
                return false;
            }
            
            const ipInt1 = this.ipToInt(ip1);
            const ipInt2 = this.ipToInt(ip2);
            const bits = parseInt(bits1, 10);
            const mask = this.getCidrMask(bits);
            
            // 检查如果减少1位掩码，两个网络是否会合并成一个
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

    // 同步滚动
    function syncScroll() {
        // 确保行号区域跟随文本区域滚动
        inputLineNumbers.scrollTop = inputRules.scrollTop;
        
        // 如果输出区域存在，也同步其滚动
        const outputLineNumbers = document.getElementById('output-line-numbers');
        const outputRulesElem = document.getElementById('output-rules');
        if (outputLineNumbers && outputRulesElem) {
            outputLineNumbers.scrollTop = outputRulesElem.scrollTop;
        }
    }

    // 更新行号显示
    function updateLineNumbers() {
        const lines = inputRules.value.split('\n');
        let lineNumbersHtml = '';
        
        for (let i = 0; i < lines.length; i++) {
            lineNumbersHtml += `<div>${i + 1}</div>`;
        }
        
        // 确保至少有一行
        if (lines.length === 0 || (lines.length === 1 && lines[0] === '')) {
            lineNumbersHtml = '<div>1</div>';
        }
        
        inputLineNumbers.innerHTML = lineNumbersHtml;
        
        // 同步滚动位置
        syncScroll();
    }

    // 规则解析和处理函数
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
            // 规则格式不正确
            return { type: 'UNKNOWN', original: rule };
        }
        
        const type = parts[0];
        const value = parts[1];
        const policy = parts.length > 2 ? parts.slice(2).join(',') : '';
        
        return { type, value, policy, original: rule };
    }

    // 检查域名是否包含或被包含
    function domainRelationship(domain1, domain2) {
        // 如果完全相同
        if (domain1 === domain2) {
            return 'SAME';
        }
        
        // 拆分为部分
        const parts1 = domain1.split('.');
        const parts2 = domain2.split('.');
        
        // 常见顶级域名列表
        const tlds = ['com', 'cn', 'net', 'org', 'gov', 'edu', 'io', 'co', 'me', 'info', 'tv'];
        const tlds2 = ['com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn'];
        
        // 检查是否是顶级域名，如果是则不参与合并
        if (tlds.includes(domain1) || tlds.includes(domain2) || 
            tlds2.includes(domain1) || tlds2.includes(domain2)) {
            return 'UNRELATED';
        }
        
        // 顶级域名最小长度检查
        if (parts1.length < 2 || parts2.length < 2) {
            return 'UNRELATED';
        }
        
        // 正确的后缀关系检查 - 确保子域名比父域名长度更长
        if (domain1.endsWith('.' + domain2) && parts1.length > parts2.length) {
            return 'SUBDOMAIN'; // domain1是domain2的子域名
        }
        
        if (domain2.endsWith('.' + domain1) && parts2.length > parts1.length) {
            return 'PARENT'; // domain1是domain2的父域名
        }
        
        return 'UNRELATED';
    }

    // 恢复被删除的规则
    function restoreRule(rule) {
        // 从已删除列表中移除
        const index = removedRulesList.findIndex(r => r.original === rule.original);
        if (index !== -1) {
            removedRulesList.splice(index, 1);
        }
        
        // 添加到合并列表
        mergedRulesList.push(rule);
        
        // 立即更新显示
        updateOutputDisplay();
        updateStats();
        
        // 添加恢复操作到详情
        detailOutput.innerHTML += `<div style="color:#27ae60;font-weight:bold;margin:5px 0;">✓ 恢复规则: ${rule.original}</div>`;
        
        // 滚动到恢复的规则位置
        setTimeout(() => {
            if (window.ruleLineMap && window.ruleLineMap[rule.original]) {
                const lineNumber = window.ruleLineMap[rule.original];
                const lineHeight = 21; // 估计的每行高度
                outputRules.scrollTop = (lineNumber - 1) * lineHeight;
                highlightLine(lineNumber);
                highlightRuleContent(rule.original);
            }
        }, 100); // 短暂延迟以确保DOM更新
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
        let lineNumberHtml = '';
        let lineCount = 1;
        
        if (mergedRulesList.length > 0) {
            const grouped = {};
            
            // 按类型分组
            mergedRulesList.forEach(rule => {
                if (!grouped[rule.type]) {
                    grouped[rule.type] = [];
                }
                grouped[rule.type].push(rule);
            });
            
            // 用于记录规则行号的映射
            window.ruleLineMap = {};
            
            // 按顺序输出域名规则
            ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'].forEach(type => {
                if (grouped[type] && grouped[type].length > 0) {
                    resultText += `# ${type} 规则\n`;
                    lineNumberHtml += `<div>${lineCount}</div>`;
                    lineCount++;
                    
                    grouped[type].forEach(rule => {
                        resultText += `${rule.original}\n`;
                        lineNumberHtml += `<div>${lineCount}</div>`;
                        // 记录规则对应的行号
                        window.ruleLineMap[rule.original] = lineCount;
                        lineCount++;
                    });
                    resultText += '\n';
                    lineNumberHtml += `<div>${lineCount}</div>`;
                    lineCount++;
                }
            });
            
            // 输出IP规则
            ['IP-CIDR', 'IP-CIDR6', 'GEOIP'].forEach(type => {
                if (grouped[type] && grouped[type].length > 0) {
                    resultText += `# ${type} 规则\n`;
                    lineNumberHtml += `<div>${lineCount}</div>`;
                    lineCount++;
                    
                    grouped[type].forEach(rule => {
                        resultText += `${rule.original}\n`;
                        lineNumberHtml += `<div>${lineCount}</div>`;
                        // 记录规则对应的行号
                        window.ruleLineMap[rule.original] = lineCount;
                        lineCount++;
                    });
                    resultText += '\n';
                    lineNumberHtml += `<div>${lineCount}</div>`;
                    lineCount++;
                }
            });
            
            // 输出其他规则
            const otherTypes = Object.keys(grouped).filter(type => 
                !['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6', 'GEOIP'].includes(type)
            );
            
            if (otherTypes.length > 0) {
                resultText += '# 其他规则\n';
                lineNumberHtml += `<div>${lineCount}</div>`;
                lineCount++;
                
                otherTypes.forEach(type => {
                    if (grouped[type] && grouped[type].length > 0) {
                        grouped[type].forEach(rule => {
                            resultText += `${rule.original}\n`;
                            lineNumberHtml += `<div>${lineCount}</div>`;
                            // 记录规则对应的行号
                            window.ruleLineMap[rule.original] = lineCount;
                            lineCount++;
                        });
                    }
                });
            }
        }
        
        // 更新UI
        outputRules.value = resultText;
        
        // 更新输出行号区域
        const outputLineNumbers = document.getElementById('output-line-numbers');
        if (outputLineNumbers) {
            outputLineNumbers.innerHTML = lineNumberHtml;
        }
    }
    
    // 更新统计信息
    function updateStats() {
        const originalRulesCount = allParsedRules.length + ignoredLinesList.length;
        originalCount.textContent = `原始规则数量: ${originalRulesCount}`;
        mergedCount.textContent = `合并后规则数量: ${mergedRulesList.length}`;
        removedCount.textContent = `移除重复/重叠规则数量: ${removedRulesList.length}`;
        
        // 更新迷你版统计信息
        const originalCountMini = document.getElementById('original-count-mini');
        const mergedCountMini = document.getElementById('merged-count-mini');
        const removedCountMini = document.getElementById('removed-count-mini');
        
        if (originalCountMini) originalCountMini.textContent = `${originalRulesCount} 条规则`;
        if (mergedCountMini) mergedCountMini.textContent = `${mergedRulesList.length} 条规则`;
        if (removedCountMini) removedCountMini.textContent = `已移除 ${removedRulesList.length} 条规则`;
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
                } else {
                    // 为每个规则添加原始行号信息
                    rule.lineIndex = index;
                    
                    // 收集重复项信息
                    const ruleKey = `${rule.type}|${rule.value}|${rule.policy}`;
                    if (!duplicateRulesMap[ruleKey]) {
                        duplicateRulesMap[ruleKey] = [];
                    }
                    duplicateRulesMap[ruleKey].push(index);
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
        let details = '<div class="detail-section">合并详情日志<br>';
        details += '============<br>';
        details += `原始规则数量: ${originalRulesCount}<br>`;
        details += `忽略的行数（空行、注释等）：${ignoredLinesList.length}<br>`;
        details += `有效规则数量: ${allParsedRules.length}<br>`;
        details += '============</div><br>';

        // 处理域名规则
        details += '<div class="detail-section">域名规则处理<br>';
        details += '------------<br>';
        
        // 处理DOMAIN规则
        if (rulesByType['DOMAIN']) {
            details += `<br>发现${rulesByType['DOMAIN'].length}条DOMAIN规则<br>`;
            
            // 去重DOMAIN规则
            const uniqueDomains = {};
            let duplicateCount = 0;
            const duplicateDomains = [];
            
            rulesByType['DOMAIN'].forEach(rule => {
                const key = rule.value + '|' + rule.policy;
                if (!uniqueDomains[key]) {
                    uniqueDomains[key] = rule;
                } else {
                    duplicateDomains.push(rule);
                    removedRulesList.push(rule);
                    duplicateCount++;
                }
            });
            
            // 显示重复的DOMAIN规则
            if (duplicateDomains.length > 0) {
                details += `发现${duplicateCount}条重复的DOMAIN规则:<br>`;
                details += `<div class="rule-grid">`;
                duplicateDomains.forEach(rule => {
                    details += `<span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule))}">${rule.value}</span>
                                <span class="locate-source" data-line="${rule.lineIndex}" data-rule-type="${rule.type}" data-rule-value="${rule.value}" data-rule-policy="${rule.policy}" title="定位原始行">🔍</span>`;
                });
                details += `</div>`;
            }
            
            // 将唯一的DOMAIN规则添加到结果
            Object.values(uniqueDomains).forEach(rule => mergedRulesList.push(rule));
            
            details += `DOMAIN规则处理完成，原有: ${rulesByType['DOMAIN'].length}，唯一: ${Object.keys(uniqueDomains).length}，删除重复: ${duplicateCount}<br>`;
        }
        
        // 处理DOMAIN-SUFFIX规则
        if (rulesByType['DOMAIN-SUFFIX']) {
            details += `<br>发现${rulesByType['DOMAIN-SUFFIX'].length}条DOMAIN-SUFFIX规则<br>`;
            
            // 去重和排序
            const uniqueSuffixes = {};
            let duplicateCount = 0;
            const duplicateSuffixes = [];
            
            rulesByType['DOMAIN-SUFFIX'].forEach(rule => {
                const key = rule.value + '|' + rule.policy;
                if (!uniqueSuffixes[key]) {
                    uniqueSuffixes[key] = rule;
                } else {
                    duplicateSuffixes.push(rule);
                    removedRulesList.push(rule);
                    duplicateCount++;
                }
            });
            
            // 显示重复的DOMAIN-SUFFIX规则
            if (duplicateSuffixes.length > 0) {
                details += `发现${duplicateCount}条重复的DOMAIN-SUFFIX规则:<br>`;
                details += `<div class="rule-grid">`;
                duplicateSuffixes.forEach(rule => {
                    details += `<span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule))}">${rule.value}</span>
                                <span class="locate-source" data-line="${rule.lineIndex}" data-rule-type="${rule.type}" data-rule-value="${rule.value}" data-rule-policy="${rule.policy}" title="定位原始行">🔍</span>`;
                });
                details += `</div>`;
            }
            
            // 对后缀进行合并 - 合并包含关系的后缀
            const sortedSuffixes = Object.values(uniqueSuffixes)
                .sort((a, b) => {
                    // 按域名长度排序，从短到长
                    const aLength = a.value.split('.').length;
                    const bLength = b.value.split('.').length;
                    if (aLength !== bLength) return aLength - bLength;
                    // 域名长度相同时按字母顺序排序
                    return a.value.localeCompare(b.value);
                });
            
            // 标记要保留和删除的规则
            for (let i = 0; i < sortedSuffixes.length; i++) {
                const rule1 = sortedSuffixes[i];
                if (rule1._processed) continue;
                
                const children = [];
                for (let j = i + 1; j < sortedSuffixes.length; j++) {
                    const rule2 = sortedSuffixes[j];
                    if (rule2._processed) continue;
                    
                    // 如果policy不同，不合并
                    if (rule1.policy !== rule2.policy) continue;
                    
                    // 检查域名关系
                    const relationship = domainRelationship(rule2.value, rule1.value);
                    if (relationship === 'SUBDOMAIN') {
                        rule2._processed = true;
                        children.push(rule2);
                    }
                }
                
                if (children.length > 0) {
                    details += `<div class="merge-group">`;
                    details += `保留 DOMAIN-SUFFIX: ${rule1.value} (包含 ${children.length} 个子域) `;
                    details += `<span class="batch-restore" data-group="${rule1.value}">【一键恢复全部】</span><br>`;
                    details += `<div class="rule-grid">`;
                    children.forEach((child) => {
                        details += `<span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(child))}">${child.value}</span>
                                    <span class="locate-source" data-line="${child.lineIndex}" data-rule-type="${child.type}" data-rule-value="${child.value}" data-rule-policy="${child.policy}" title="定位原始行">🔍</span>`;
                        // 为每个组内规则添加组标识
                        child._group = rule1.value;
                        removedRulesList.push(child);
                    });
                    details += `</div></div>`;
                }
            }
            
            // 将剩余未处理的域名添加到结果
            const remainingSuffixes = sortedSuffixes.filter(rule => !rule._processed);
            remainingSuffixes.forEach(rule => mergedRulesList.push(rule));
            
            details += `DOMAIN-SUFFIX规则处理完成，原有: ${rulesByType['DOMAIN-SUFFIX'].length}，中间去重: ${Object.keys(uniqueSuffixes).length}，最终保留: ${remainingSuffixes.length}，删除重复: ${duplicateCount}，删除被包含子域: ${sortedSuffixes.length - remainingSuffixes.length - duplicateCount}<br>`;
        }

        // 处理DOMAIN-KEYWORD规则
        if (rulesByType['DOMAIN-KEYWORD']) {
            details += `<br>发现${rulesByType['DOMAIN-KEYWORD'].length}条DOMAIN-KEYWORD规则<br>`;
            
            // 去重DOMAIN-KEYWORD规则
            const uniqueKeywords = {};
            let duplicateCount = 0;
            const duplicateKeywords = [];
            
            rulesByType['DOMAIN-KEYWORD'].forEach(rule => {
                const key = rule.value + '|' + rule.policy;
                if (!uniqueKeywords[key]) {
                    uniqueKeywords[key] = rule;
                } else {
                    duplicateKeywords.push(rule);
                    removedRulesList.push(rule);
                    duplicateCount++;
                }
            });
            
            // 显示重复的DOMAIN-KEYWORD规则
            if (duplicateKeywords.length > 0) {
                details += `发现${duplicateCount}条重复的DOMAIN-KEYWORD规则:<br>`;
                details += `<div class="rule-grid">`;
                duplicateKeywords.forEach(rule => {
                    details += `<span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule))}">${rule.value}</span>
                                <span class="locate-source" data-line="${rule.lineIndex}" data-rule-type="${rule.type}" data-rule-value="${rule.value}" data-rule-policy="${rule.policy}" title="定位原始行">🔍</span>`;
                });
                details += `</div>`;
            }
            
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
            
            details += `DOMAIN-KEYWORD规则处理完成，原有: ${rulesByType['DOMAIN-KEYWORD'].length}，去重后: ${keywordRules.length}，最终保留: ${finalKeywordRules.length}，删除重复: ${duplicateCount}，删除冗余: ${containedCount}<br>`;
        }
        
        // 处理DOMAIN和DOMAIN-SUFFIX之间的关联
        details += '<br>检查DOMAIN与DOMAIN-SUFFIX之间的关联<br>';
        
        const domainsToKeep = [];
        let containedCount = 0;
        const containedDomains = [];
        
        for (const domainRule of mergedRulesList.filter(r => r.type === 'DOMAIN')) {
            let isContained = false;
            let containingRule = null;
            
            for (const suffixRule of mergedRulesList.filter(r => r.type === 'DOMAIN-SUFFIX')) {
                if (domainRule.policy !== suffixRule.policy) continue;
                
                // 检查是否是常见顶级域名
                const tlds = ['.com', '.cn', '.net', '.org', '.gov', '.edu', '.io', '.co'];
                const suffixParts = suffixRule.value.split('.');
                const isTLD = suffixParts.length <= 2 && tlds.some(tld => suffixRule.value.endsWith(tld));
                
                if (isTLD) {
                    // 不使用顶级域名作为匹配条件
                    continue;
                }
                
                // 检查domain是否匹配suffix
                if (domainRule.value === suffixRule.value || 
                    domainRule.value.endsWith('.' + suffixRule.value)) {
                        isContained = true;
                        containingRule = suffixRule;
                        containedDomains.push({domain: domainRule, suffix: suffixRule});
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
        
        // 显示被包含的DOMAIN规则
        if (containedDomains.length > 0) {
            details += `<br>以下${containedCount}条DOMAIN规则被DOMAIN-SUFFIX规则包含:<br>`;
            
            // 按照包含它们的后缀规则分组
            const groupedByContainingSuffix = {};
            containedDomains.forEach(item => {
                const suffixValue = item.suffix.value;
                if (!groupedByContainingSuffix[suffixValue]) {
                    groupedByContainingSuffix[suffixValue] = [];
                }
                groupedByContainingSuffix[suffixValue].push(item.domain);
                // 为每个组内规则添加组标识
                item.domain._group = suffixValue;
            });
            
            // 对每个后缀展示其包含的域名
            for (const suffix in groupedByContainingSuffix) {
                details += `<div class="merge-group">`;
                details += `后缀 <b>${suffix}</b> 包含以下域名: `;
                details += `<span class="batch-restore" data-group="${suffix}">【一键恢复全部】</span><br>`;
                details += `<div class="rule-grid">`;
                groupedByContainingSuffix[suffix].forEach(domain => {
                    details += `<span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(domain))}">${domain.value}</span>
                                <span class="locate-source" data-line="${domain.lineIndex}" data-rule-type="${domain.type}" data-rule-value="${domain.value}" data-rule-policy="${domain.policy}" title="定位原始行">🔍</span>`;
                });
                details += `</div></div>`;
            }
        }
        
        details += `DOMAIN与DOMAIN-SUFFIX关系处理完成，移除被包含的DOMAIN规则: ${containedCount}<br>`;
        
        details += '</div>';
        
        // 处理IP规则
        details += '<div class="detail-section">IP规则处理<br>';
        details += '------------<br>'; 
        
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
                
                // 第一步：去除被其他CIDR完全包含的子规则
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
                                details += `<span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule1))}">${rule1.original}</span>
                                            <span class="locate-source" data-line="${rule1.lineIndex}" data-rule-type="${rule1.type}" data-rule-value="${rule1.value}" data-rule-policy="${rule1.policy}" title="定位原始行">🔍</span><br>`;
                                removedRulesList.push(rule1);
                                processedCidrs.add(i);
                                break;
                            }
                        } catch (e) {
                            details += `错误: 处理IP-CIDR时出错: ${e.message}<br>`;
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
                                    details += `<div class="rule-grid">`;
                                    details += `<span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule1))}">${rule1.original}</span>
                                                <span class="locate-source" data-line="${rule1.lineIndex}" data-rule-type="${rule1.type}" data-rule-value="${rule1.value}" data-rule-policy="${rule1.policy}" title="定位原始行">🔍</span>`;
                                    details += `<span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule2))}">${rule2.original}</span>
                                                <span class="locate-source" data-line="${rule2.lineIndex}" data-rule-type="${rule2.type}" data-rule-value="${rule2.value}" data-rule-policy="${rule2.policy}" title="定位原始行">🔍</span>`;
                                    details += `</div>`;
                                    
                                    if (!removedRulesList.includes(rule1)) removedRulesList.push(rule1);
                                    if (!removedRulesList.includes(rule2)) removedRulesList.push(rule2);
                                    break;
                                }
                            } catch (e) {
                                details += `错误: 合并IP-CIDR时出错: ${e.message}<br>`;
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
            
            details += `<br>IP-CIDR规则处理完成，原有规则数: ${cidrRules.length}，合并后: ${mergedCidrRules.length}，删除: ${cidrRules.length - mergedCidrRules.length}<br>`;
        }
        
        details += '</div>';
        
        // 处理其他类型的规则
        const processedTypes = ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR'];
        const otherRules = allParsedRules.filter(rule => !processedTypes.includes(rule.type));
        
        if (otherRules.length > 0) {
            details += '<div class="detail-section">其他类型规则处理<br>';
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
                    details += `删除重复规则: <span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(rule))}">${rule.original}</span>
                                <span class="locate-source" data-line="${rule.lineIndex}" data-rule-type="${rule.type}" data-rule-value="${rule.value}" data-rule-policy="${rule.policy}" title="定位原始行">🔍</span><br>`;
                    removedRulesList.push(rule);
                    duplicateCount++;
                }
            });
            
            // 将其他类型的规则添加到结果
            Object.values(uniqueOtherRules).forEach(rule => mergedRulesList.push(rule));
            
            details += `其他规则处理完成，原有: ${otherRules.length}，唯一: ${Object.keys(uniqueOtherRules).length}，删除重复: ${duplicateCount}<br>`;
            details += '</div>';
        }
        
        // 统计结果
        details += '<div class="detail-section">';
        details += '<br>=========<br>';
        details += `合并后规则数: ${mergedRulesList.length}<br>`;
        details += `删除的重复或冗余规则数量: ${removedRulesList.length}<br>`;
        details += `忽略的行数: ${ignoredLinesList.length}<br>`;
        
        // 计算总数核对
        const totalAccounted = mergedRulesList.length + removedRulesList.length + ignoredLinesList.length;
        details += `总计: ${totalAccounted} / ${originalRulesCount}<br>`;
        
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
        
        // 添加交互提示
        detailOutput.innerHTML += `
        <div class="interaction-tips">
            <h4>交互功能使用说明：</h4>
            <ul>
                <li>点击任意<span class="removed-rule">被删除的规则</span>可将其恢复到结果中</li>
                <li>点击规则旁的<span class="locate-source-example">🔍</span>图标可定位到输入文本中的原始位置，多次点击可在重复项之间循环切换</li>
                <li>点击保留规则旁的<span class="delete-option">[删除]</span>按钮可将其从结果中移除</li>
                <li>点击<span class="batch-restore-example">【一键恢复全部】</span>可恢复同组所有规则</li>
            </ul>
        </div>`;
        
        // 使用事件委托
        detailOutput.addEventListener('click', function(e) {
            // 检查是否点击了删除的规则
            if (e.target.classList.contains('removed-rule')) {
                const ruleData = JSON.parse(decodeURIComponent(e.target.getAttribute('data-rule')));
                restoreRule(ruleData);
                updateOutputDisplay();
                updateStats();
                
                // 如果规则被恢复，则滚动到其在输出区域的位置
                if (window.ruleLineMap && window.ruleLineMap[ruleData.original]) {
                    const lineNumber = window.ruleLineMap[ruleData.original];
                    const lineHeight = 21; // 估计的每行高度
                    outputRules.scrollTop = (lineNumber - 1) * lineHeight;
                    // 闪烁效果突出显示
                    highlightLine(lineNumber);
                }
            }
            // 检查是否点击了批量恢复按钮
            else if (e.target.classList.contains('batch-restore')) {
                const groupName = e.target.getAttribute('data-group');
                if (groupName) {
                    // 找到属于该组的所有被移除规则
                    const groupRules = removedRulesList.filter(r => r._group === groupName);
                    
                    if (groupRules.length > 0) {
                        // 创建批量恢复提示
                        const message = `<div style="color:#27ae60;font-weight:bold;margin:10px 0;padding:5px;background:#e8f8f0;border-radius:5px;">
                            ✓ 批量恢复 ${groupName} 组内的 ${groupRules.length} 条规则
                        </div>`;
                        detailOutput.innerHTML += message;
                        
                        // 逐个恢复规则，但不更新显示
                        let lastRestoredRule = null;
                        groupRules.forEach(rule => {
                            // 从已删除列表中移除
                            const index = removedRulesList.findIndex(r => r.original === rule.original);
                            if (index !== -1) {
                                removedRulesList.splice(index, 1);
                            }
                            // 添加到合并列表
                            mergedRulesList.push(rule);
                            lastRestoredRule = rule;
                        });
                        
                        // 批量处理完成后才更新显示，提高效率
                        updateOutputDisplay();
                        updateStats();
                        
                        // 隐藏已恢复组的"一键恢复"按钮
                        e.target.style.display = 'none';
                        
                        // 如果有最后恢复的规则，滚动到其位置
                        if (lastRestoredRule && window.ruleLineMap && window.ruleLineMap[lastRestoredRule.original]) {
                            const lineNumber = window.ruleLineMap[lastRestoredRule.original];
                            const lineHeight = 21; // 估计的每行高度
                            outputRules.scrollTop = (lineNumber - 1) * lineHeight;
                            highlightLine(lineNumber);
                        }
                    }
                }
            }
            // 检查是否点击了删除选项
            else if (e.target.classList.contains('delete-option')) {
                e.stopPropagation(); // 阻止事件冒泡
                const ruleData = JSON.parse(decodeURIComponent(e.target.getAttribute('data-rule')));
                
                // 将规则从合并列表移除
                const index = mergedRulesList.findIndex(r => r.original === ruleData.original);
                if (index !== -1) {
                    // 从合并列表移除
                    const removedRule = mergedRulesList.splice(index, 1)[0];
                    // 添加到已删除列表
                    removedRulesList.push(removedRule);
                    
                    // 更新显示
                    updateOutputDisplay();
                    updateStats();
                    
                    // 更新删除操作到详情
                    const newDetail = `<div style="color:#e74c3c;margin:5px 0;">✗ 手动删除规则: <span class="removed-rule" data-rule="${encodeURIComponent(JSON.stringify(removedRule))}">${removedRule.original}</span></div>`;
                    detailOutput.innerHTML += newDetail;
                }
            }
            // 检查是否点击了定位源码按钮
            else if (e.target.classList.contains('locate-source')) {
                const lineIndex = parseInt(e.target.getAttribute('data-line'));
                const ruleType = e.target.getAttribute('data-rule-type');
                const ruleValue = e.target.getAttribute('data-rule-value');
                const rulePolicy = e.target.getAttribute('data-rule-policy');
                
                if (!isNaN(lineIndex)) {
                    // 构建规则键
                    const ruleKey = `${ruleType}|${ruleValue}|${rulePolicy}`;
                    
                    // 获取所有重复项的行号
                    const allDuplicateLines = duplicateRulesMap[ruleKey] || [lineIndex];
                    
                    // 如果当前规则没有记录当前索引，则初始化为0
                    if (currentDuplicateIndices[ruleKey] === undefined) {
                        currentDuplicateIndices[ruleKey] = 0;
                    } else {
                        // 否则移动到下一个索引，如果到达末尾则循环回到开始
                        currentDuplicateIndices[ruleKey] = (currentDuplicateIndices[ruleKey] + 1) % allDuplicateLines.length;
                    }
                    
                    // 获取当前应该显示的行号
                    const currentLineIndex = allDuplicateLines[currentDuplicateIndices[ruleKey]];
                    
                    // 添加指示器显示当前查看的是第几个重复项
                    const totalDuplicates = allDuplicateLines.length;
                    const currentPosition = currentDuplicateIndices[ruleKey] + 1;
                    
                    // 更新按钮文本显示当前位置
                    e.target.textContent = `🔍 ${currentPosition}/${totalDuplicates}`;
                    
                    // 添加激活状态样式
                    document.querySelectorAll('.locate-source').forEach(btn => btn.classList.remove('active'));
                    e.target.classList.add('active');
                    
                    // 激活输入区域并高亮
                    const inputContainer = document.querySelector('.input-area .code-container');
                    const outputContainer = document.querySelector('.output-area .code-container');
                    const detailContainer = document.querySelector('.detail-container');
                    
                    inputContainer.classList.add('active-section');
                    outputContainer.classList.remove('active-section');
                    detailContainer.classList.remove('active-section');
                    
                    // 高亮显示输入文本中对应的行，传递位置信息
                    highlightInputLine(currentLineIndex, currentPosition, totalDuplicates);
                    
                    // 滚动到输入区域中的行
                    const lineHeight = 21; // 每行的大致高度
                    inputRules.scrollTop = currentLineIndex * lineHeight;
                    
                    // 添加闪烁效果
                    inputRules.classList.add('flash-scroll');
                    setTimeout(() => {
                        inputRules.classList.remove('flash-scroll');
                    }, 1000);
                    
                    // 如果在较小屏幕上，滚动到输入区域顶部
                    if (window.innerWidth <= 1100) {
                        // 获取输入区域的位置
                        const inputAreaRect = inputContainer.getBoundingClientRect();
                        // 如果输入区域不在视口中，滚动到它
                        if (inputAreaRect.top < 0 || inputAreaRect.bottom > window.innerHeight) {
                            inputContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
                        }
                    }
                }
            }
        });
        
        // 为被删除的规则添加提示信息
        addRestoreHints();
        
        // 直接在这里添加删除选项
        addDeleteOptionsToDetails();
    }

    // 高亮显示特定行
    function highlightLine(lineNumber) {
        const outputLineNumbers = document.getElementById('output-line-numbers');
        const lineElements = outputLineNumbers.getElementsByTagName('div');
        
        if (lineNumber > 0 && lineNumber <= lineElements.length) {
            const lineElement = lineElements[lineNumber - 1];
            
            // 移除所有行的高亮
            for (let i = 0; i < lineElements.length; i++) {
                lineElements[i].classList.remove('highlight-line');
            }
            
            // 添加高亮
            lineElement.classList.add('highlight-line');
            
            // 2秒后移除高亮
            setTimeout(() => {
                lineElement.classList.remove('highlight-line');
            }, 3000);
        }
    }
    
    // 高亮显示规则内容
    function highlightRuleContent(ruleText) {
        // 创建临时元素以获取规则文本位置
        const textArea = outputRules;
        const text = textArea.value;
        
        // 找到规则在文本中的位置
        const index = text.indexOf(ruleText);
        if (index === -1) return;
        
        // 计算规则所在行
        const beforeText = text.substring(0, index);
        const linesBefore = beforeText.split('\n').length - 1;
        
        // 创建高亮标记（创建一个临时的元素来显示高亮效果）
        const highlightMarker = document.createElement('div');
        highlightMarker.className = 'highlight-content-marker';
        highlightMarker.style.position = 'absolute';
        highlightMarker.style.height = '21px'; // 行高
        highlightMarker.style.width = 'calc(100% - 30px)'; // 宽度减去填充
        highlightMarker.style.backgroundColor = '#a8e4c8';
        highlightMarker.style.top = `${(linesBefore) * 21 + 15}px`; // 15px是文本区域的填充
        highlightMarker.style.left = '15px'; // 文本区域的填充
        highlightMarker.style.zIndex = '5';
        highlightMarker.style.opacity = '0.6';
        highlightMarker.style.pointerEvents = 'none'; // 使其不拦截点击
        
        // 添加高亮标记
        const outputContainer = document.querySelector('.output-container');
        outputContainer.style.position = 'relative';
        outputContainer.appendChild(highlightMarker);
        
        // 添加动画
        highlightMarker.style.animation = 'content-pulse 3s';
        
        // 3秒后移除高亮标记
        setTimeout(() => {
            outputContainer.removeChild(highlightMarker);
        }, 3000);
    }
    
    // 修改添加删除选项的方法，不再绑定事件（已通过事件委托处理）
    function addDeleteOptionsToDetails() {
        // 查找详情中提到"保留"的规则
        const detailLines = detailOutput.innerHTML.split('<br>');
        let updatedDetails = '';
        
        detailLines.forEach(line => {
            if (line.includes('保留') && !line.includes('class="delete-option"')) {
                // 提取规则内容
                const match = line.match(/保留\s+([\w-]+:\s+[^,]+)/);
                if (match) {
                    const ruleInfo = match[1];
                    const typeParts = ruleInfo.split(':');
                    if (typeParts.length >= 2) {
                        const ruleType = typeParts[0].trim();
                        const ruleValue = typeParts[1].trim();
                        
                        // 查找对应的完整规则
                        const targetRule = mergedRulesList.find(r => 
                            r.type === ruleType && r.value === ruleValue
                        );
                        
                        if (targetRule) {
                            // 添加删除选项
                            const deleteBtn = `<span class="delete-option" data-rule="${encodeURIComponent(JSON.stringify(targetRule))}">[删除]</span>`;
                            line += ` ${deleteBtn}`;
                        }
                    }
                }
            }
            updatedDetails += line + '<br>';
        });
        
        detailOutput.innerHTML = updatedDetails;
        
        // 不再这里绑定事件，已通过事件委托处理
    }

    // 为被删除的规则添加提示信息
    function addRestoreHints() {
        setTimeout(() => {
            const removedRules = document.querySelectorAll('.removed-rule');
            removedRules.forEach(rule => {
                // 检查是否已有提示
                if (!rule.querySelector('.restore-hint')) {
                    const hint = document.createElement('span');
                    hint.className = 'restore-hint';
                    hint.textContent = '点击恢复此规则';
                    hint.style.position = 'absolute';
                    hint.style.top = '-25px';
                    hint.style.left = '50%';
                    hint.style.transform = 'translateX(-50%)';
                    rule.style.position = 'relative';
                    rule.appendChild(hint);
                }
            });
        }, 200); // 短暂延迟确保DOM已更新
    }

    // 复制到剪贴板
    function copyToClipboard(text) {
        if (!text.trim()) {
            alert('没有内容可复制');
            return;
        }
        
        if (navigator.clipboard && window.isSecureContext) {
            // 使用现代Clipboard API
            navigator.clipboard.writeText(text)
                .then(() => {
                    alert('已复制到剪贴板');
                })
                .catch(err => {
                    console.error('复制失败:', err);
                    // 回退到传统方法
                    fallbackCopyToClipboard(text);
                });
        } else {
            // 使用传统方法
            fallbackCopyToClipboard(text);
        }
    }
    
    // 传统剪贴板复制方法
    function fallbackCopyToClipboard(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        
        try {
            document.execCommand('copy');
            alert('已复制到剪贴板');
        } catch (err) {
            console.error('复制失败:', err);
            alert('复制失败，请手动复制');
        }
        
        document.body.removeChild(textArea);
    }

    // 下载规则文件
    function downloadRules() {
        if (!outputRules.value.trim()) {
            alert('没有规则可下载');
            return;
        }
        
        // 处理规则文本，移除行号
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
        mergedCount.textContent = '合并后规则数量: 0';
        removedCount.textContent = '移除重复/重叠规则数量: 0';
        updateLineNumbers(); // 更新行号
    }

    // 加载示例
    function loadExample() {
        inputRules.value = `# 域名规则示例 - 测试重复和重叠规则
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

# IP-CIDR规则 - 测试包含关系和相邻网段合并
IP-CIDR,192.168.0.0/16,DIRECT  # 更大的网段
IP-CIDR,192.168.1.0/24,DIRECT  # 被上面的网段包含
IP-CIDR,192.168.2.0/24,DIRECT  # 被上面的网段包含
IP-CIDR,10.0.0.0/8,DIRECT     # 更大的网段
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

    // 高亮显示输入文本中的行
    function highlightInputLine(lineIndex, currentPosition = null, totalPositions = null) {
        // 获取输入文本内容
        const text = inputRules.value;
        const lines = text.split('\n');
        
        // 确保行号在范围内
        if (lineIndex < 0 || lineIndex >= lines.length) return;
        
        // 创建一个临时标记
        const marker = document.createElement('div');
        marker.className = 'input-highlight-marker';
        marker.style.position = 'absolute';
        marker.style.height = '21px';
        marker.style.width = 'calc(100% - 80px)';
        marker.style.backgroundColor = '#ffecb3';
        marker.style.top = `${lineIndex * 21 + 15}px`;
        marker.style.left = '50px';
        marker.style.zIndex = '5';
        marker.style.opacity = '0.7';
        marker.style.pointerEvents = 'none';
        marker.style.animation = 'input-highlight-pulse 2s';
        
        // 如果提供了位置信息，显示当前位置/总数
        if (currentPosition !== null && totalPositions !== null) {
            marker.setAttribute('data-position', `${currentPosition}/${totalPositions}`);
        }
        
        // 添加高亮标记
        const inputContainer = document.querySelector('.input-area .code-container');
        inputContainer.style.position = 'relative';
        
        // 移除现有的高亮标记
        const existingMarkers = inputContainer.querySelectorAll('.input-highlight-marker');
        existingMarkers.forEach(m => inputContainer.removeChild(m));
        
        // 添加新标记
        inputContainer.appendChild(marker);
        
        // 5秒后自动移除高亮
        setTimeout(() => {
            if (inputContainer.contains(marker)) {
                inputContainer.removeChild(marker);
            }
        }, 5000);
        
        // 高亮行号
        highlightInputLineNumber(lineIndex);
    }

    // 高亮输入文本的行号
    function highlightInputLineNumber(lineIndex) {
        const lineNumbers = inputLineNumbers.querySelectorAll('div');
        
        // 移除所有现有高亮
        lineNumbers.forEach(ln => ln.classList.remove('highlight-line'));
        
        // 添加高亮
        if (lineIndex >= 0 && lineIndex < lineNumbers.length) {
            lineNumbers[lineIndex].classList.add('highlight-line');
            
            // 5秒后移除高亮
            setTimeout(() => {
                lineNumbers[lineIndex].classList.remove('highlight-line');
            }, 5000);
        }
    }

    // 添加区域聚焦处理
    function setupFocusHandling() {
        const inputContainer = document.querySelector('.input-area .code-container');
        const outputContainer = document.querySelector('.output-area .code-container');
        const detailContainer = document.querySelector('.detail-container');
        
        // 去除所有活动状态
        function removeActiveClass() {
            inputContainer.classList.remove('active-section');
            outputContainer.classList.remove('active-section');
            detailContainer.classList.remove('active-section');
        }
        
        // 添加点击聚焦处理
        inputContainer.addEventListener('click', function() {
            removeActiveClass();
            inputContainer.classList.add('active-section');
        });
        
        outputContainer.addEventListener('click', function() {
            removeActiveClass();
            outputContainer.classList.add('active-section');
        });
        
        detailContainer.addEventListener('click', function() {
            removeActiveClass();
            detailContainer.classList.add('active-section');
        });
        
        // 点击定位按钮时需要显示输入区域
        document.addEventListener('click', function(e) {
            if (e.target.classList.contains('locate-source')) {
                removeActiveClass();
                inputContainer.classList.add('active-section');
                
                // 如果在小屏幕上，确保详情区域也可见
                if (window.innerWidth <= 1100) {
                    detailContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    // 等待滚动结束后再滚动到输入区域
                    setTimeout(() => {
                        inputContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    }, 100);
                }
            }
        });
    }
    
    // 页面加载完成后设置聚焦处理
    setupFocusHandling();
}); 
