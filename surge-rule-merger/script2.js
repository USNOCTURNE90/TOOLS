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
        
        // 检查后缀关系
        if (domain1.endsWith('.' + domain2)) {
            return 'SUBDOMAIN'; // domain1是domain2的子域名
        }
        
        if (domain2.endsWith('.' + domain1)) {
            return 'PARENT'; // domain1是domain2的父域名
        }
        
        return 'UNRELATED';
    } 