import { describe, it, expect } from 'vitest';
import yaml from 'js-yaml';
import { urlToClashProxy } from '../../functions/utils/url-to-clash.js';
import { convertClashProxyToUrl } from '../../functions/utils/clash-to-url.js';
import { convertVlessToUrl } from '../../src/utils/protocols/converters/vless.js';
import { generateBuiltinClashConfig } from '../../functions/modules/subscription/builtin-clash-generator.js';

// Synthetic material exercises long encryption values without storing real node credentials.
const encryption = `mlkem768x25519plus.native.0rtt.${'Ab_9-'.repeat(320)}`;
const baseUrl = 'vless://00000000-0000-4000-8000-000000000001@proxy.example.com:443';
const params = new URLSearchParams({
    encryption,
    flow: 'xtls-rprx-vision',
    type: 'ws',
    host: 'tunnel.example.com',
    path: 'test-ws',
    security: 'tls',
    sni: 'tunnel.example.com',
});
const uri = `${baseUrl}?${params}#Encrypted`;

describe('VLESS Encryption preservation', () => {
    it('preserves encryption and Vision over WebSocket in generated Mihomo YAML', () => {
        const config = yaml.load(generateBuiltinClashConfig(uri, { ruleLevel: 'minimal' }));
        expect(config.proxies[0]).toMatchObject({
            encryption,
            flow: 'xtls-rprx-vision',
            network: 'ws',
            tls: true,
            'ws-opts': { path: 'test-ws', headers: { Host: 'tunnel.example.com' } },
        });
        expect(config.proxies[0]['skip-cert-verify']).not.toBe(true);
    });

    it.each([
        ['backend', convertClashProxyToUrl],
        ['frontend', convertVlessToUrl],
    ])('preserves encryption through the %s round trip', (_, convert) => {
        const proxy = urlToClashProxy(uri);
        const exported = convert(proxy);
        expect(new URL(exported).searchParams.get('encryption')).toBe(encryption);
        expect(urlToClashProxy(exported)).toMatchObject({
            encryption,
            flow: 'xtls-rprx-vision',
            network: 'ws',
        });
    });

    it.each(['', '?encryption=none', '?encryption='])(
        'keeps ordinary VLESS unchanged for %s',
        (suffix) => {
            const proxy = urlToClashProxy(baseUrl + suffix);
            expect(proxy).not.toHaveProperty('encryption');
            expect(new URL(convertClashProxyToUrl(proxy)).searchParams.get('encryption')).toBe(
                'none'
            );
        }
    );
});
