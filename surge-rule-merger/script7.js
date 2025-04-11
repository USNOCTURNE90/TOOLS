        // 统计结果
        details += '<div class="detail-section">';
        details += '<br>=========<br>';
        details += `合并后规则数量: ${mergedRulesList.length}<br>`;
        details += `删除的重复或冗余规则数量: ${removedRulesList.length}<br>`;
        details += `忽略的行数: ${ignoredLinesList.length}<br>`;
        
        // 计算总数核对
        const totalAccounted = mergedRulesList.length + removedRulesList.length + ignoredLinesList.length;
        details += `总计数: ${totalAccounted} / ${originalRulesCount}<br>`;
        
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
}); 