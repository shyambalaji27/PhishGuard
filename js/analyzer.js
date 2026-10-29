/**
 * PhishGuard - Explainable Heuristic URL Analysis Engine
 * 
 * Provides transparent, client-side, multi-layer heuristic security checks.
 * This is an explainable rule-based engine designed for awareness and education,
 * not an infallible AI/ML model or a replacement for commercial enterprise threat intel.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.URLAnalyzer = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // High-value brand names targeted by phishing campaigns
  const KNOWN_BRANDS = [
    'google', 'paypal', 'apple', 'microsoft', 'amazon', 'facebook', 'instagram',
    'netflix', 'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'binance',
    'coinbase', 'metamask', 'blockchain', 'yahoo', 'outlook', 'dropbox',
    'linkedin', 'twitter', 'github', 'whatsapp', 'telegram', 'adobe', 'steam',
    'discord', 'spotify', 'ebay', 'walmart', 'usps', 'fedex', 'dhl', 'roblox'
  ];

  // Common URL shortening domains that obfuscate destination
  const KNOWN_SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'buff.ly',
    'adf.ly', 'bit.do', 'tiny.cc', 'cutt.ly', 'shorte.st', 'rb.gy', 'v.gd',
    'clck.ru', 's.id', 'shorturl.at', 'bl.ink', 'hyperurl.co', 'soo.gd',
    'rebrand.ly', 'tny.im', 'bc.vc', 'u.to', 'po.st'
  ]);

  // TLDs frequently abused in low-cost, disposable phishing kits
  const SUSPICIOUS_TLDS = new Set([
    'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'work', 'click', 'fit',
    'rest', 'buzz', 'cam', 'icu', 'surf', 'loan', 'bar', 'mom', 'monster',
    'country', 'stream', 'kim', 'science', 'gdn', 'racing'
  ]);

  // Sensitive keywords commonly found in credential-harvesting lures
  const SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification', 'update',
    'banking', 'secure', 'security', 'account', 'confirm', 'confirmation',
    'password', 'credential', 'authenticate', 'authentication', 'wallet',
    'recover', 'recovery', 'billing', 'invoice', 'unlock', 'support-service',
    'kyc', 'validate', 'validation', 'webscr', 'passcode', 'security-alert',
    'reactivate', 'suspend', 'suspended', 'appeal'
  ];

  /**
   * Helper: Calculate Levenshtein distance between two strings
   */
  function levenshteinDistance(a, b) {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;
    const matrix = [];
    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }
    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }
    return matrix[b.length][a.length];
  }

  /**
   * Helper: Calculate Shannon Entropy for domain randomness (DGA detection)
   */
  function calculateEntropy(str) {
    if (!str || str.length === 0) return 0;
    const frequencies = {};
    for (const char of str) {
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const char in frequencies) {
      const p = frequencies[char] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  /**
   * Helper: Extract base domain and subdomains
   */
  function extractDomainParts(hostname) {
    const parts = hostname.toLowerCase().split('.').filter(Boolean);
    if (parts.length <= 1) {
      return {
        baseDomain: hostname,
        domainName: hostname || '',
        subdomains: [],
        subdomainString: '',
        tld: ''
      };
    }
    
    // Simple 2-part ccTLD handling (e.g., .co.uk, .com.br, .gov.in)
    const secondLevelTlds = new Set(['co.uk', 'gov.uk', 'ac.uk', 'com.br', 'com.au', 'co.in', 'net.in', 'gov.in', 'co.jp', 'com.mx']);
    const lastTwo = parts.slice(-2).join('.');
    
    let tld = parts[parts.length - 1];
    let domainName = '';
    let subdomains = [];

    if (secondLevelTlds.has(lastTwo) && parts.length >= 3) {
      tld = lastTwo;
      domainName = parts[parts.length - 3];
      subdomains = parts.slice(0, -3);
    } else {
      domainName = parts[parts.length - 2];
      subdomains = parts.slice(0, -2);
    }

    return {
      baseDomain: `${domainName}.${tld}`,
      domainName,
      subdomains,
      subdomainString: subdomains.join('.'),
      tld
    };
  }

  /**
   * Main Analyzer Class
   */
  class URLAnalyzer {
    /**
     * Validate and normalize user-provided URL with intelligent error tolerance
     */
    static normalizeUrl(rawUrl) {
      if (!rawUrl || typeof rawUrl !== 'string') {
        throw new Error('Please enter a valid URL.');
      }

      // Strip outer whitespace, wrapping quotes, angle brackets, and parentheses
      let trimmed = rawUrl.trim().replace(/^["'<\[\(\s]+|["'>\]\)\s]+$/g, '');

      if (!trimmed) {
        throw new Error('Please enter a valid URL to analyze.');
      }

      // Block dangerous non-HTTP schemes
      const forbiddenSchemeRegex = /^(javascript|data|file|vbscript|about|blob):/i;
      if (forbiddenSchemeRegex.test(trimmed)) {
        throw new Error('Unsupported or potentially unsafe URL scheme. Only HTTP and HTTPS are permitted.');
      }

      // Handle protocol-relative URLs (e.g., //example.com)
      if (trimmed.startsWith('//')) {
        trimmed = 'https:' + trimmed;
      }

      // Fix common protocol typos (e.g., https:/domain.com, https//domain.com, https:domain.com)
      trimmed = trimmed.replace(/^https?:\/+(?!\/)/i, 'https://');
      trimmed = trimmed.replace(/^https?\/\//i, 'https://');
      trimmed = trimmed.replace(/^https?:(?!\/\/)/i, 'https://');

      // Check if user entered only protocol without destination
      if (/^https?:\/\/?$/i.test(trimmed)) {
        throw new Error('Incomplete URL. Please include the website domain (e.g., "google.com" or "https://chase.com").');
      }

      // If user typed a single word without dots, slashes, or ports (e.g., "google" or "paypal"), auto-append .com
      if (!trimmed.includes('.') && !trimmed.includes('/') && !trimmed.includes(':') && !/^https?:\/\//i.test(trimmed)) {
        trimmed = trimmed + '.com';
      }

      // Prepend https:// if no scheme is provided
      if (!/^https?:\/\//i.test(trimmed)) {
        trimmed = 'https://' + trimmed;
      }

      // Safely encode unencoded spaces in path or query parameters
      trimmed = trimmed.replace(/\s+/g, '%20');

      try {
        const parsed = new URL(trimmed);
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
          throw new Error('Only HTTP and HTTPS URLs can be analyzed.');
        }
        if (!parsed.hostname || parsed.hostname.length < 2) {
          throw new Error('URL hostname is invalid or missing.');
        }
        return {
          normalizedUrl: parsed.href,
          parsed
        };
      } catch (err) {
        throw new Error(err.message || 'Malformed URL format. Please check for syntax errors.');
      }
    }

    /**
     * Comprehensive URL Analysis Engine
     */
    static analyze(rawUrl) {
      const { normalizedUrl, parsed } = this.normalizeUrl(rawUrl);
      const checks = [];
      const suspiciousPatterns = [];
      let totalRiskPoints = 0;

      const hostname = parsed.hostname.toLowerCase();
      const pathname = parsed.pathname;
      const search = parsed.search;
      const fullUrlLower = normalizedUrl.toLowerCase();
      const domainParts = extractDomainParts(hostname);

      // ----------------------------------------------------
      // Check 1: HTTPS Usage & Transport Security
      // ----------------------------------------------------
      {
        const isHttps = parsed.protocol === 'https:';
        let status = 'pass';
        let points = 0;
        let explanation = 'URL uses encrypted HTTPS protocol.';

        if (!isHttps) {
          status = 'warn';
          points = 18;
          explanation = 'URL uses unencrypted HTTP. Data sent over this connection can be intercepted.';
          suspiciousPatterns.push('Unencrypted HTTP connection');

          // Check if plain HTTP combined with login keywords
          const hasLogin = SUSPICIOUS_KEYWORDS.some(kw => fullUrlLower.includes(kw));
          if (hasLogin) {
            status = 'fail';
            points = 26;
            explanation = 'Unencrypted HTTP combined with sensitive login/auth keywords. Severe credential interception risk.';
            suspiciousPatterns.push('HTTP with auth keywords');
          }
        }

        checks.push({
          id: 'https_check',
          name: 'HTTPS Transport Security',
          category: 'Encryption',
          status,
          points,
          explanation,
          details: `Protocol: ${parsed.protocol.replace(':', '').toUpperCase()}`
        });
        totalRiskPoints += points;
      }

      // ----------------------------------------------------
      // Check 2: IP Address as Hostname
      // ----------------------------------------------------
      {
        // IPv4 regex (including octal/hex variants)
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const isIp = ipv4Regex.test(hostname) || /^\[?[a-f0-9:]+\]?$/i.test(hostname);
        let status = 'pass';
        let points = 0;
        let explanation = 'Domain name uses standard FQDN rather than a raw IP address.';

        if (isIp) {
          status = 'fail';
          points = 35;
          explanation = 'URL hostname is a raw IP address. Legitimate organizations rarely use bare IP addresses for public sites.';
          suspiciousPatterns.push(`Raw IP address host: ${hostname}`);
        }

        checks.push({
          id: 'ip_address',
          name: 'IP Address as Hostname',
          category: 'Host Identity',
          status,
          points,
          explanation,
          details: isIp ? `Detected direct IP host: ${hostname}` : 'Standard domain name used.'
        });
        totalRiskPoints += points;
      }

      // ----------------------------------------------------
      // Check 3: Excessive Subdomains / Deep Nesting
      // ----------------------------------------------------
      {
        const subCount = domainParts.subdomains.length;
        let status = 'pass';
        let points = 0;
        let explanation = `Normal subdomain structure (${subCount} subdomain${subCount === 1 ? '' : 's'}).`;

        if (subCount >= 4) {
          status = 'fail';
          points = 25;
          explanation = `Excessive subdomain nesting (${subCount} subdomains). Attackers often chain subdomains to masquerade as legitimate domains.`;
          suspiciousPatterns.push(`Deep subdomain nesting (${subCount} levels)`);
        } else if (subCount === 3) {
          status = 'warn';
          points = 14;
          explanation = `Multiple subdomains detected (${subCount} subdomains). Can be an indicator of multi-tenant or spoofing infrastructure.`;
          suspiciousPatterns.push(`Multiple subdomains (${subCount} levels)`);
        }

        checks.push({
          id: 'subdomain_depth',
          name: 'Subdomain Nesting Depth',
          category: 'Domain Structure',
          status,
          points,
          explanation,
          details: `Subdomains: ${domainParts.subdomainString || 'None'}`
        });
        totalRiskPoints += points;
      }

      // ----------------------------------------------------
      // Check 4: Suspicious URL Length
      // ----------------------------------------------------
      {
        const urlLen = normalizedUrl.length;
        const hostLen = hostname.length;
        let status = 'pass';
        let points = 0;
        let explanation = `URL length is within standard parameters (${urlLen} characters).`;

        if (urlLen > 150) {
          status = 'fail';
          points = 22;
          explanation = `Unusually long URL (${urlLen} characters). Long URLs are frequently used to conceal tokens or push the real domain off-screen.`;
          suspiciousPatterns.push(`Excessive URL length (${urlLen} chars)`);
        } else if (urlLen > 85) {
          status = 'warn';
          points = 10;
          explanation = `Longer than average URL (${urlLen} characters). Common in complex tracking or multi-parameter phishing lures.`;
        }

        if (hostLen > 40) {
          points += 8;
          status = status === 'pass' ? 'warn' : status;
          explanation += ` Hostname itself is unusually long (${hostLen} chars).`;
        }

        checks.push({
          id: 'url_length',
          name: 'URL & Host Length',
          category: 'Lexical Analysis',
          status,
          points,
          explanation,
          details: `Total length: ${urlLen} chars | Host length: ${hostLen} chars`
        });
        totalRiskPoints += points;
      }

      // ----------------------------------------------------
      // Check 5: URL Shortener Detection
      // ----------------------------------------------------
      {
        const isShortener = KNOWN_SHORTENERS.has(hostname) || KNOWN_SHORTENERS.has(domainParts.baseDomain);
        let status = 'pass';
        let points = 0;
        let explanation = 'URL does not belong to a recognized shortening service.';

        if (isShortener) {
          status = 'warn';
          points = 20;
          explanation = 'Known URL shortener detected. Shorteners hide the final destination and are routinely used in phishing campaigns.';
          suspiciousPatterns.push(`Shortening service: ${hostname}`);
        }

        checks.push({
          id: 'url_shortener',
          name: 'URL Shortener Detection',
          category: 'Obfuscation',
          status,
          points,
          explanation,
          details: isShortener ? `Matches shortener database: ${hostname}` : 'Direct URL destination'
        });
        totalRiskPoints += points;
      }

      // ----------------------------------------------------
      // Check 6: Misleading Brand Spoofing & Typosquatting
      // ----------------------------------------------------
      {
        let status = 'pass';
        let points = 0;
        let explanation = 'No deceptive brand impersonation or typosquatting detected in domain.';
        let details = 'Domain does not mimic high-target brands.';

        let brandFoundInSubOrPath = null;
        let typosquattedBrand = null;

        // A. Check if a high-value brand is in subdomains or path while NOT being the registered domain
        for (const brand of KNOWN_BRANDS) {
          // If the actual domain is the legitimate brand domain (e.g., google.com or paypal.com), skip
          if (domainParts.domainName === brand) {
            continue;
          }

          // Check if brand appears in subdomains or domain prefix/suffix
          if (domainParts.subdomainString.includes(brand) || 
              (domainParts.domainName.includes(brand) && domainParts.domainName !== brand)) {
            brandFoundInSubOrPath = brand;
            break;
          }

          // Check if brand is in path AND accompanied by login/credential context
          const pathLower = pathname.toLowerCase();
          const queryLower = search.toLowerCase();
          if (pathLower.includes('/' + brand) && (
              pathLower.includes('login') || pathLower.includes('signin') ||
              pathLower.includes('auth') || pathLower.includes('verify') ||
              pathLower.includes('account') || pathLower.includes('wallet') ||
              pathLower.includes('credential') || queryLower.includes('account')
          )) {
            brandFoundInSubOrPath = `${brand} (auth portal path)`;
            break;
          }
        }

        // B. Levenshtein typosquatting test against domain name
        if (!brandFoundInSubOrPath) {
          for (const brand of KNOWN_BRANDS) {
            if (domainParts.domainName === brand) continue;
            // Only compare if lengths are comparable
            if (Math.abs(domainParts.domainName.length - brand.length) <= 2) {
              const dist = levenshteinDistance(domainParts.domainName, brand);
              // Distance of 1 or 2 is a strong indicator of typosquatting
              if (dist === 1 || (dist === 2 && brand.length >= 6)) {
                typosquattedBrand = { brand, dist };
                break;
              }
            }
          }
        }

        if (brandFoundInSubOrPath) {
          status = 'fail';
          points = 35;
          explanation = `Deceptive brand reference detected: "${brandFoundInSubOrPath}". The target brand appears in the URL structure while the true domain is "${domainParts.baseDomain}".`;
          details = `Target brand spoofing: ${brandFoundInSubOrPath} on host ${hostname}`;
          suspiciousPatterns.push(`Brand spoofing: ${brandFoundInSubOrPath}`);
        } else if (typosquattedBrand) {
          status = 'fail';
          points = 32;
          explanation = `Possible typosquatting target: mimics "${typosquattedBrand.brand}" (Levenshtein distance: ${typosquattedBrand.dist}). Often indicates character substitution (e.g., '1' for 'l', '0' for 'o').`;
          details = `Typosquatting candidate: "${domainParts.domainName}" resembles "${typosquattedBrand.brand}"`;
          suspiciousPatterns.push(`Typosquatting: ${domainParts.domainName} ~ ${typosquattedBrand.brand}`);
        }

        checks.push({
          id: 'brand_spoofing',
          name: 'Brand Spoofing & Typosquatting',
          category: 'Identity Verification',
          status,
          points,
          explanation,
          details
        });
        totalRiskPoints += points;
      }

      // ----------------------------------------------------
      // Check 7: Unusual Characters & Encoded Sequences
      // ----------------------------------------------------
      {
        const hyphenCount = (hostname.match(/-/g) || []).length;
        const percentCount = (normalizedUrl.match(/%/g) || []).length;
        const doubleSlashInPath = pathname.includes('//');
        const excessiveDots = (hostname.match(/\./g) || []).length >= 4;

        let status = 'pass';
        let points = 0;
        let reasons = [];

        if (hyphenCount >= 3) {
          points += 18;
          reasons.push(`${hyphenCount} hyphens in domain`);
          suspiciousPatterns.push(`Heavy hyphen usage in host (${hyphenCount})`);
        } else if (hyphenCount === 2) {
          points += 8;
          reasons.push(`2 hyphens in domain`);
        }

        if (percentCount >= 3) {
          points += 15;
          reasons.push(`${percentCount} encoded '%XX' hex characters`);
          suspiciousPatterns.push(`High percent-encoding density (${percentCount})`);
        }

        if (doubleSlashInPath) {
          points += 14;
          reasons.push(`Suspicious double-slash '//' in path`);
          suspiciousPatterns.push('Double slash in URL path');
        }

        if (excessiveDots) {
          points += 10;
          reasons.push('High dot frequency in hostname');
        }

        if (points >= 20) {
          status = 'fail';
        } else if (points > 0) {
          status = 'warn';
        }

        const explanation = reasons.length > 0 
          ? `Unusual lexical characters detected: ${reasons.join(', ')}.`
          : 'Clean character structure without excessive hyphens, hex encodings, or abnormal separators.';

        checks.push({
          id: 'unusual_characters',
          name: 'Unusual Characters & Encodings',
          category: 'Lexical Analysis',
          status,
          points,
          explanation,
          details: `Hyphens: ${hyphenCount} | Percent encodings: ${percentCount} | Double slashes: ${doubleSlashInPath ? 'Yes' : 'No'}`
        });
        totalRiskPoints += points;
      }

      // ----------------------------------------------------
      // Check 8: '@' Symbol in URL Structure
      // ----------------------------------------------------
      {
        const hasAtSymbol = normalizedUrl.includes('@');
        let status = 'pass';
        let points = 0;
        let explanation = 'No "@" symbol in URL authority or path.';

        if (hasAtSymbol) {
          status = 'fail';
          points = 35;
          explanation = 'The "@" symbol is present. Browsers treat anything before the "@" as userinfo credentials and navigate to the domain after the "@", effectively deceiving users.';
          suspiciousPatterns.push('Deceptive "@" symbol structure');
        }

        checks.push({
          id: 'at_symbol',
          name: '"@" Symbol Deception',
          category: 'Structure Deception',
          status,
          points,
          explanation,
          details: hasAtSymbol ? 'Detected "@" symbol in URL' : 'None detected'
        });
        totalRiskPoints += points;
      }

      // ----------------------------------------------------
      // Check 9: Suspicious Urgency & Credential Keywords
      // ----------------------------------------------------
      {
        const matchedKeywords = [];
        for (const kw of SUSPICIOUS_KEYWORDS) {
          if (fullUrlLower.includes(kw)) {
            matchedKeywords.push(kw);
          }
        }

        let status = 'pass';
        let points = 0;
        let explanation = 'No high-risk credential-harvesting keywords found in URL tokens.';

        if (matchedKeywords.length >= 3) {
          status = 'fail';
          points = 24;
          explanation = `Multiple high-pressure security/credential keywords found: [${matchedKeywords.slice(0, 4).join(', ')}]. Highly characteristic of credential theft lures.`;
          suspiciousPatterns.push(`Multiple sensitive keywords: ${matchedKeywords.slice(0, 3).join(', ')}`);
        } else if (matchedKeywords.length >= 1) {
          status = 'warn';
          points = 10;
          explanation = `Contains credential/account keyword: "${matchedKeywords[0]}". Common in legitimate login portals but warrants inspection when combined with other indicators.`;
        }

        checks.push({
          id: 'suspicious_keywords',
          name: 'Credential & Urgency Keywords',
          category: 'Content Heuristics',
          status,
          points,
          explanation,
          details: matchedKeywords.length > 0 ? `Matched: ${matchedKeywords.join(', ')}` : 'None detected'
        });
        totalRiskPoints += points;
      }

      // ----------------------------------------------------
      // Check 10: Punycode & Homoglyph Internationalized Domains
      // ----------------------------------------------------
      {
        const hasPunycode = hostname.includes('xn--');
        // Check for non-ASCII or mixed scripts in hostname
        const hasNonAscii = /[^\u0000-\u007F]/.test(hostname);
        let status = 'pass';
        let points = 0;
        let explanation = 'Standard ASCII characters used in domain name without Punycode disguise.';

        if (hasPunycode) {
          status = 'fail';
          points = 30;
          explanation = 'Punycode ("xn--") detected. Attackers use Punycode/IDN homoglyphs (e.g., Cyrillic "а" instead of Latin "a") to visually clone trusted brand URLs.';
          suspiciousPatterns.push(`Punycode IDN homoglyph: ${hostname}`);
        } else if (hasNonAscii) {
          status = 'warn';
          points = 20;
          explanation = 'Non-ASCII characters detected in domain string. Potential internationalized homograph risk.';
          suspiciousPatterns.push('Non-ASCII domain characters');
        }

        checks.push({
          id: 'punycode_homoglyph',
          name: 'Punycode & Homoglyph Attacks',
          category: 'Character Cloaking',
          status,
          points,
          explanation,
          details: hasPunycode ? 'Punycode (xn--) encoding active' : (hasNonAscii ? 'Non-ASCII characters found' : 'Standard ASCII domain')
        });
        totalRiskPoints += points;
      }

      // ----------------------------------------------------
      // Check 11: Unusual / Non-standard Web Ports
      // ----------------------------------------------------
      {
        const port = parsed.port;
        let status = 'pass';
        let points = 0;
        let explanation = 'Standard web port (80 or 443) or default port used.';

        if (port) {
          const standardPorts = ['80', '443'];
          if (!standardPorts.includes(port)) {
            status = 'warn';
            points = 18;
            explanation = `Non-standard port :${port} specified. Phishing kits and unauthorized staging servers often run on alternate ports like 8080, 8443, or high-number ports.`;
            suspiciousPatterns.push(`Non-standard port: :${port}`);
          }
        }

        checks.push({
          id: 'unusual_port',
          name: 'Port Analysis',
          category: 'Network Transport',
          status,
          points,
          explanation,
          details: port ? `Specified port: :${port}` : 'Standard default port (80/443)'
        });
        totalRiskPoints += points;
      }

      // ----------------------------------------------------
      // Check 12: Open Redirection Indicators
      // ----------------------------------------------------
      {
        const redirectParams = ['url', 'redirect', 'next', 'dest', 'target', 'link', 'r', 'out', 'view', 'goto'];
        let status = 'pass';
        let points = 0;
        let detectedParam = null;
        let explanation = 'No external open redirection parameters detected in URL query.';

        const searchParams = parsed.searchParams;
        for (const p of redirectParams) {
          if (searchParams.has(p)) {
            const val = searchParams.get(p) || '';
            if (/^https?:\/\//i.test(val) || val.startsWith('//')) {
              detectedParam = { param: p, destination: val };
              break;
            }
          }
        }

        if (detectedParam) {
          status = 'fail';
          points = 24;
          explanation = `Open redirect pattern detected in query parameter "?${detectedParam.param}=". Phishers exploit open redirects on legitimate sites to bypass email filters.`;
          suspiciousPatterns.push(`Open redirect param: ?${detectedParam.param}`);
        }

        checks.push({
          id: 'open_redirect',
          name: 'Open Redirection Parameters',
          category: 'Payload Chaining',
          status,
          points,
          explanation,
          details: detectedParam ? `Parameter ?${detectedParam.param}= points to external target` : 'No open redirect parameters found'
        });
        totalRiskPoints += points;
      }

      // ----------------------------------------------------
      // Check 13: High-Abuse / Suspicious TLD
      // ----------------------------------------------------
      {
        const tld = domainParts.tld;
        let status = 'pass';
        let points = 0;
        let explanation = `Top-level domain (.${tld}) has standard reputation profile.`;

        if (SUSPICIOUS_TLDS.has(tld)) {
          status = 'warn';
          points = 16;
          explanation = `Top-level domain (.${tld}) is statistically prevalent in disposable spam and phishing infrastructure.`;
          suspiciousPatterns.push(`High-abuse TLD: .${tld}`);
        }

        checks.push({
          id: 'suspicious_tld',
          name: 'Top-Level Domain Reputation',
          category: 'Domain Registry',
          status,
          points,
          explanation,
          details: `TLD: .${tld || 'unknown'}`
        });
        totalRiskPoints += points;
      }

      // ----------------------------------------------------
      // Check 14: Domain Shannon Entropy (DGA Detection)
      // ----------------------------------------------------
      {
        const entropy = calculateEntropy(domainParts.domainName);
        let status = 'pass';
        let points = 0;
        let explanation = `Domain character distribution is natural (Entropy: ${entropy.toFixed(2)} bits).`;

        // Normal english word domains typically have entropy between 2.0 and 3.5
        // DGA or random character strings typically exceed 3.8 - 4.2
        if (entropy > 3.85 && domainParts.domainName.length > 9) {
          status = 'warn';
          points = 16;
          explanation = `High randomness score (${entropy.toFixed(2)} bits). May indicate an algorithmic domain generation (DGA) or machine-generated domain.`;
          suspiciousPatterns.push(`High domain entropy (${entropy.toFixed(2)} bits)`);
        }

        checks.push({
          id: 'domain_entropy',
          name: 'Domain Randomness (Shannon Entropy)',
          category: 'Algorithmic Detection',
          status,
          points,
          explanation,
          details: `Entropy: ${entropy.toFixed(2)} bits (Threshold: 3.85 bits)`
        });
        totalRiskPoints += points;
      }

      // ----------------------------------------------------
      // Final Score Normalization & Categorization
      // ----------------------------------------------------
      // Clamp between 0 and 100
      const finalScore = Math.min(100, Math.max(0, Math.round(totalRiskPoints)));

      let verdict = 'SAFE';
      let riskLevel = 'Low Risk';
      let summary = 'This URL exhibited no significant red flags during heuristic inspection. All core integrity and domain identity checks passed.';
      let recommendation = 'Safe to proceed under normal caution. Always confirm you are on the expected site before entering credentials.';

      if (finalScore >= 60) {
        verdict = 'PHISHING';
        riskLevel = 'High Risk';
        summary = 'Multiple severe security anomalies were identified. This URL matches patterns frequently associated with fraudulent websites, credential theft, or malware distribution.';
        recommendation = 'DO NOT CLICK or enter credentials. Close the tab immediately. If received via email or SMS, report it as a phishing attempt.';
      } else if (finalScore >= 30) {
        verdict = 'SUSPICIOUS';
        riskLevel = 'Medium Risk';
        summary = 'Several unusual characteristics were observed (e.g., non-standard domain structure, shortened destination, or security keyword combinations).';
        recommendation = 'Exercise heightened caution. Verify the sender and independently navigate to the official domain instead of following this link directly.';
      }

      // Count pass / warn / fail breakdown
      const summaryStats = {
        totalChecks: checks.length,
        passed: checks.filter(c => c.status === 'pass').length,
        warnings: checks.filter(c => c.status === 'warn').length,
        failed: checks.filter(c => c.status === 'fail').length
      };

      return {
        url: normalizedUrl,
        originalInput: rawUrl,
        parsed: {
          hostname,
          baseDomain: domainParts.baseDomain,
          pathname,
          search,
          protocol: parsed.protocol
        },
        score: finalScore,
        verdict,
        riskLevel,
        summary,
        recommendation,
        checks,
        suspiciousPatterns: Array.from(new Set(suspiciousPatterns)),
        stats: summaryStats,
        timestamp: new Date().toISOString()
      };
    }
  }

  return URLAnalyzer;
}));
