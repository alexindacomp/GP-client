// DEV-ONLY browser preview entry: installs the mock before the real renderer boots.
import './preview.css';
import { installMockGp } from './mockGp';

installMockGp();
if (new URLSearchParams(window.location.search).get('frame') !== '0') {
  document.documentElement.classList.add('preview-frame');
}
void import('../src/main');
