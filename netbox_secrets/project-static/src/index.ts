import { initSecrets } from './secrets';

if (document.readyState !== 'loading') {
  initSecrets();
} else {
  document.addEventListener('DOMContentLoaded', initSecrets);
}
