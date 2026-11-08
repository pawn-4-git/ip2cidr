/**
 * ip2cidr GitHub Pages Interactive Documentation Script
 */
(function () {
  'use strict';

  const announcer = document.getElementById('live-announcer');
  let announceTimeoutId = null;

  function announce(message) {
    if (!announcer) return;
    if (announceTimeoutId) {
      clearTimeout(announceTimeoutId);
    }
    announceTimeoutId = setTimeout(() => {
      announcer.textContent = message;
    }, 80);
  }

  /* ========================================================================
     1. Theme Switcher (System / Light / Dark)
     ======================================================================== */
  const themeBtn = document.getElementById('theme-toggle');
  const themeLabel = document.getElementById('theme-toggle-label');
  const rootEl = document.documentElement;
  const darkQuery = window.matchMedia('(prefers-color-scheme: dark)');

  const THEME_MODES = ['system', 'light', 'dark'];
  const THEME_LABELS = {
    system: 'テーマ: 自動',
    light: 'テーマ: ライト',
    dark: 'テーマ: ダーク',
  };

  let currentThemeMode = 'system';
  try {
    const saved = localStorage.getItem('ip2cidr-theme');
    if (saved && THEME_MODES.includes(saved)) {
      currentThemeMode = saved;
    }
  } catch (_) {
    // Ignore storage access errors in restricted contexts
  }

  function applyTheme(mode) {
    currentThemeMode = mode;
    if (mode === 'system') {
      rootEl.removeAttribute('data-theme');
    } else {
      rootEl.setAttribute('data-theme', mode);
    }
    if (themeLabel) {
      themeLabel.textContent = THEME_LABELS[mode];
    }
  }

  applyTheme(currentThemeMode);

  if (themeBtn) {
    themeBtn.addEventListener('click', () => {
      const nextIndex = (THEME_MODES.indexOf(currentThemeMode) + 1) % THEME_MODES.length;
      const nextMode = THEME_MODES[nextIndex];
      applyTheme(nextMode);
      try {
        localStorage.setItem('ip2cidr-theme', nextMode);
      } catch (_) {
        // Ignore storage errors
      }
      announce(THEME_LABELS[nextMode] + ' に切り替えました');
    });
  }

  // Listen to OS color-scheme changes per modern-web-guidance
  darkQuery.addEventListener('change', () => {
    if (currentThemeMode === 'system') {
      applyTheme('system');
    }
  });

  /* ========================================================================
     2. Copy to Clipboard for Code Blocks
     ======================================================================== */
  async function copyText(text, buttonEl) {
    try {
      await navigator.clipboard.writeText(text.trim());
      const originalText = buttonEl.dataset.originalLabel || buttonEl.textContent;
      buttonEl.dataset.originalLabel = originalText;
      buttonEl.dataset.copied = 'true';
      buttonEl.textContent = 'コピー完了';
      announce('コードをクリップボードにコピーしました');

      setTimeout(() => {
        buttonEl.dataset.copied = 'false';
        buttonEl.textContent = originalText;
      }, 2000);
    } catch (_) {
      announce('コピーに失敗しました。手動で選択してコピーしてください。');
    }
  }

  document.querySelectorAll('[data-copy-target]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-copy-target');
      const codeEl = targetId ? document.getElementById(targetId) : null;
      if (codeEl) {
        copyText(codeEl.textContent || '', btn);
      }
    });
  });

  /* ========================================================================
     3. Interactive CLI Command Builder & Output Simulator
     ======================================================================== */
  const inputSourceSelect = document.getElementById('builder-input-source');
  const outputModeSelect = document.getElementById('builder-output-mode');
  const outputDestSelect = document.getElementById('builder-output-dest');
  const includeRawCheckbox = document.getElementById('builder-include-raw');
  const generatedCmdCode = document.getElementById('builder-generated-cmd');
  const generatedOutputCode = document.getElementById('builder-generated-output');
  const outputPreviewLabel = document.getElementById('builder-preview-label');

  function buildCommandAndPreview() {
    if (!inputSourceSelect || !outputModeSelect || !outputDestSelect || !includeRawCheckbox) {
      return;
    }

    const inputSource = inputSourceSelect.value;
    const outputMode = outputModeSelect.value;
    const outputDest = outputDestSelect.value;
    const includeRaw = includeRawCheckbox.checked;

    const args = [];
    let prefixPipe = '';

    if (inputSource === 'file') {
      args.push('-f ips.txt');
    } else if (inputSource === 'stdin') {
      prefixPipe = 'cat ips.txt | ';
    }

    if (outputMode === 'ip') {
      args.push('-m ip');
    } else if (outputMode === 'cidr-explicit') {
      args.push('--cidr');
    }

    if (outputDest === 'csv') {
      const fileName = outputMode === 'ip' ? 'result_ip.csv' : 'result_cidr.csv';
      args.push('--csv ' + fileName);
    }

    if (includeRaw) {
      args.push('--raw');
    }

    if (inputSource === 'args') {
      args.push('8.8.8.8 8.8.8.4 1.1.1.1');
    }

    const argString = args.length > 0 ? ' ' + args.join(' ') : '';
    const fullCommand = prefixPipe + 'java -jar build/libs/ip2cidr-1.0.0.jar' + argString;

    if (generatedCmdCode) {
      generatedCmdCode.textContent = fullCommand;
    }

    // Build realistic output preview
    const statusHeader = [
      '[WHOIS] Starting resolution for 3 IP address(es) (sorted in ascending order)...',
      '[WHOIS] [1/3] Querying whois for 1.1.1.1...',
      '[WHOIS] [1/3] 1.1.1.1 -> Resolved CIDR: 1.1.1.0/24 (Range: 1.1.1.0 - 1.1.1.255, Country: AU, NetName: APNIC-LABS, Registrant: APNIC and Cloudflare DNS Resolver project)',
      '[WHOIS] [2/3] Waiting 5 second(s) for rate limit before querying 8.8.8.4...',
      '[WHOIS] [2/3] Querying whois for 8.8.8.4...',
      '[WHOIS] [2/3] 8.8.8.4 -> Resolved CIDR: 8.8.8.0/24 (Range: 8.8.8.0 - 8.8.8.255, Country: US, NetName: GOGL, Registrant: Google LLC)',
      '[WHOIS] [3/3] 8.8.8.8 -> Skipped (matched cached CIDR: 8.8.8.0/24, Country: US, Registrant: Google LLC)',
      '[WHOIS] Completed resolution: 3 IP address(es) aggregated into 2 CIDR block(s).',
    ].join('\n');

    let previewText = '';
    if (outputDest === 'csv') {
      const fileName = outputMode === 'ip' ? 'result_ip.csv' : 'result_cidr.csv';
      if (outputPreviewLabel) {
        outputPreviewLabel.textContent = '標準出力ログ + 生成される ' + fileName + ' の内容';
      }
      if (outputMode === 'ip') {
        const rawHeader = includeRaw ? ',RawWhoisOutput' : '';
        const rawCol1 = includeRaw ? ',"inetnum: 1.1.1.0 - 1.1.1.255 ..."' : '';
        const rawCol2 = includeRaw ? ',"NetRange: 8.8.8.0 - 8.8.8.255 ..."' : '';
        previewText =
          statusHeader +
          '\nCSV output written to: /path/to/' +
          fileName +
          '\n\n# --- ' +
          fileName +
          ' ---\n' +
          'IPAddress,CIDR,NetworkIP,PrefixLength,AllCIDRs,IPRange,Country,Registrant,NetName,Descriptions,AdminContacts,TechContacts,AbuseContacts' +
          rawHeader +
          '\n' +
          '1.1.1.1,1.1.1.0/24,1.1.1.0,24,1.1.1.0/24,1.1.1.0 - 1.1.1.255,AU,APNIC and Cloudflare DNS Resolver project,APNIC-LABS,APNIC and Cloudflare DNS Resolver project,AIC3-AP,AIC3-AP,helpdesk@apnic.net' +
          rawCol1 +
          '\n' +
          '8.8.8.4,8.8.8.0/24,8.8.8.0,24,8.8.8.0/24,8.8.8.0 - 8.8.8.255,US,Google LLC,GOGL,,ZG39-ARIN,ZG39-ARIN,network-abuse@google.com' +
          rawCol2 +
          '\n' +
          '8.8.8.8,8.8.8.0/24,8.8.8.0,24,8.8.8.0/24,8.8.8.0 - 8.8.8.255,US,Google LLC,GOGL,,ZG39-ARIN,ZG39-ARIN,network-abuse@google.com' +
          rawCol2;
      } else {
        const rawHeader = includeRaw ? ',RawWhoisOutput' : '';
        const rawCol1 = includeRaw ? ',"inetnum: 1.1.1.0 - 1.1.1.255 ..."' : '';
        const rawCol2 = includeRaw ? ',"NetRange: 8.8.8.0 - 8.8.8.255 ..."' : '';
        previewText =
          statusHeader +
          '\nCSV output written to: /path/to/' +
          fileName +
          '\n\n# --- ' +
          fileName +
          ' ---\n' +
          'CIDR,NetworkIP,PrefixLength,AllCIDRs,IPRange,MatchedIPs,Country,Registrant,NetName,Descriptions,AdminContacts,TechContacts,AbuseContacts' +
          rawHeader +
          '\n' +
          '1.1.1.0/24,1.1.1.0,24,1.1.1.0/24,1.1.1.0 - 1.1.1.255,1.1.1.1,AU,APNIC and Cloudflare DNS Resolver project,APNIC-LABS,APNIC and Cloudflare DNS Resolver project,AIC3-AP,AIC3-AP,helpdesk@apnic.net' +
          rawCol1 +
          '\n' +
          '8.8.8.0/24,8.8.8.0,24,8.8.8.0/24,8.8.8.0 - 8.8.8.255,"8.8.8.4; 8.8.8.8",US,Google LLC,GOGL,,ZG39-ARIN,ZG39-ARIN,network-abuse@google.com' +
          rawCol2;
      }
    } else {
      if (outputPreviewLabel) {
        outputPreviewLabel.textContent =
          outputMode === 'ip' ? '標準出力プレビュー（IP単位モード）' : '標準出力プレビュー（CIDR単位モード）';
      }
      const rawBlock1 = includeRaw
        ? '\nRaw Whois Output:\ninetnum:        1.1.1.0 - 1.1.1.255\nnetname:        APNIC-LABS\ncountry:        AU'
        : '';
      const rawBlock2 = includeRaw
        ? '\nRaw Whois Output:\nNetRange:       8.8.8.0 - 8.8.8.255\nCIDR:           8.8.8.0/24\nOrgName:        Google LLC'
        : '';

      if (outputMode === 'ip') {
        previewText =
          statusHeader +
          '\n' +
          [
            'IP Address      : 1.1.1.1',
            'CIDR            : 1.1.1.0/24',
            'IP Range        : 1.1.1.0 - 1.1.1.255',
            'Country         : AU',
            'Registrant      : APNIC and Cloudflare DNS Resolver project',
            'NetName         : APNIC-LABS',
            'Descriptions    : APNIC and Cloudflare DNS Resolver project',
            'Admin Contacts  : AIC3-AP',
            'Tech Contacts   : AIC3-AP',
            'Abuse Contacts  : helpdesk@apnic.net' + rawBlock1,
            '------------------------------------------------------------',
            'IP Address      : 8.8.8.4',
            'CIDR            : 8.8.8.0/24',
            'IP Range        : 8.8.8.0 - 8.8.8.255',
            'Country         : US',
            'Registrant      : Google LLC',
            'NetName         : GOGL',
            'Admin Contacts  : ZG39-ARIN',
            'Tech Contacts   : ZG39-ARIN',
            'Abuse Contacts  : network-abuse@google.com' + rawBlock2,
            '------------------------------------------------------------',
            'IP Address      : 8.8.8.8',
            'CIDR            : 8.8.8.0/24',
            'IP Range        : 8.8.8.0 - 8.8.8.255',
            'Country         : US',
            'Registrant      : Google LLC',
            'NetName         : GOGL',
            'Admin Contacts  : ZG39-ARIN',
            'Tech Contacts   : ZG39-ARIN',
            'Abuse Contacts  : network-abuse@google.com' + rawBlock2,
          ].join('\n');
      } else {
        previewText =
          statusHeader +
          '\n' +
          [
            'CIDR            : 1.1.1.0/24',
            'IP Range        : 1.1.1.0 - 1.1.1.255',
            'Matched IPs     : 1.1.1.1',
            'Country         : AU',
            'Registrant      : APNIC and Cloudflare DNS Resolver project',
            'NetName         : APNIC-LABS',
            'Descriptions    : APNIC and Cloudflare DNS Resolver project',
            'Admin Contacts  : AIC3-AP',
            'Tech Contacts   : AIC3-AP',
            'Abuse Contacts  : helpdesk@apnic.net' + rawBlock1,
            '------------------------------------------------------------',
            'CIDR            : 8.8.8.0/24',
            'IP Range        : 8.8.8.0 - 8.8.8.255',
            'Matched IPs     : 8.8.8.4, 8.8.8.8',
            'Country         : US',
            'Registrant      : Google LLC',
            'NetName         : GOGL',
            'Admin Contacts  : ZG39-ARIN',
            'Tech Contacts   : ZG39-ARIN',
            'Abuse Contacts  : network-abuse@google.com' + rawBlock2,
          ].join('\n');
      }
    }

    if (generatedOutputCode) {
      generatedOutputCode.textContent = previewText;
    }
  }

  [inputSourceSelect, outputModeSelect, outputDestSelect, includeRawCheckbox].forEach((control) => {
    if (control) {
      control.addEventListener('change', buildCommandAndPreview);
    }
  });

  buildCommandAndPreview();
})();

