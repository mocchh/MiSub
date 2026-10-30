import { describe, it, expect } from 'vitest';
import yaml from 'js-yaml';
import { urlToClashProxy } from '../../functions/utils/url-to-clash.js';
import { convertClashProxyToUrl } from '../../functions/utils/clash-to-url.js';
import { convertHysteriaToUrl } from '../../src/utils/protocols/converters/hysteria.js';
import { generateBuiltinClashConfig } from '../../functions/modules/subscription/builtin-clash-generator.js';

const fingerprint = '0123456789abcdef'.repeat(4);
const baseProxy = {
    name: 'Pinned HY2',
    type: 'hysteria2',
    server: 'hy2.example.com',
    port: 443,
    password: 'test-password',
    sni: 'hy2.example.com',
    'skip-cert-verify': false,
    fingerprint,
};

describe('Hysteria2 certificate pin preservation', () => {
    it.each(['hysteria2', 'hy2'])('preserves %s URI pins in generated Mihomo YAML', (scheme) => {
        const uri = `${scheme}://test-password@hy2.example.com:443?sni=hy2.example.com&insecure=0&allowInsecure=0&pinSHA256=${fingerprint}#Pinned`;
        const config = yaml.load(generateBuiltinClashConfig(uri, { ruleLevel: 'minimal' }));
        expect(config.proxies[0].fingerprint).toBe(fingerprint);
        expect(config.proxies[0]['skip-cert-verify']).not.toBe(true);
    });

    it.each([
        ['backend', convertClashProxyToUrl],
        ['frontend', convertHysteriaToUrl],
    ])('preserves pins through the %s YAML-to-URI-to-Clash path', (_, convert) => {
        const uri = convert({ ...baseProxy, 'client-fingerprint': 'chrome' });
        expect(new URL(uri).searchParams.get('pinSHA256')).toBe(fingerprint);
        const proxy = urlToClashProxy(uri);
        expect(proxy.fingerprint).toBe(fingerprint);
        expect(proxy['skip-cert-verify']).not.toBe(true);
    });

    it('does not treat a browser TLS fingerprint as a certificate pin', () => {
        const { fingerprint: unused, ...proxy } = baseProxy;
        const uri = convertHysteriaToUrl({ ...proxy, 'client-fingerprint': 'chrome' });
        expect(new URL(uri).searchParams.has('pinSHA256')).toBe(false);
        expect(urlToClashProxy(uri)).not.toHaveProperty('fingerprint');
    });

    it('preserves a pin even when insecure is explicitly enabled', () => {
        const uri = `hy2://test-password@hy2.example.com:443?insecure=1&pinSHA256=${fingerprint}`;
        expect(urlToClashProxy(uri)).toMatchObject({ fingerprint, 'skip-cert-verify': true });
    });
});
