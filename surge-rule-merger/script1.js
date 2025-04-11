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

    // 初始化行号显示
    updateLineNumbers();

    // 监听输入变化以更新行号
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
        
        // 确保至少有一行
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