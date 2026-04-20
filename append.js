const fs = require('fs');

const appJsPath = '/home/deepak/Programming/sudhanshu/Promptwar/promptwar/app.js';
const tailPath = '/home/deepak/Programming/sudhanshu/Promptwar/promptwar/gs_module_tail.js';

let appJsContent = fs.readFileSync(appJsPath, 'utf8');
let tailContent = fs.readFileSync(tailPath, 'utf8');

if (!appJsContent.includes('_initAnalyticsAndPerf')) {
  if (appJsContent.trim().endsWith('})')) {
     appJsContent += '\n      .catch(() => { /* FCM token error */ });\n\n' + 
    '    // Handle incoming FCM foreground messages\n' +
    '    messaging.onMessage(payload => {\n' +
    '      const { title = \'VenueFlow\', body = \'\' } = payload.notification || {};\n' +
    '      showToast(\'info\', title, body);\n\n' +
    '      // Increment notification badge on attendee view\n' +
    '      const badge = document.getElementById(\'notif-badge\');\n' +
    '      if (badge) {\n' +
    '        const count = (parseInt(badge.textContent, 10) || 0) + 1;\n' +
    '        badge.style.display = \'flex\';\n' +
    '        badge.textContent   = count;\n' +
    '      }\n' +
    '      _updateAnalyticsCounter(\'ana-fcm-sent\', 1);\n' +
    '      _logAnalyticsEvent(\'fcm_received\', { title });\n' +
    '    });\n' +
    '  }).catch(() => { /* Permission denied */ });\n}\n\n' + tailContent;
  } else {
    appJsContent += '\n' + tailContent;
  }
  fs.writeFileSync(appJsPath, appJsContent);
  console.log('Appended module successfully.');
} else {
  console.log('Module already present.');
}
