import * as CryptoJS from 'crypto-js';

import { AwsSignatureInputData } from './aws-signature-input.model';

/**
 * Amazon web services (AWS) Signature version 4 - EC2 API requests signing tool.
 * @class AwsSignature
 */
export class AwsSignature {
    constructor() {}

    /**
     * Generates the signature
     *
     * @param {AwsSignatureInputData} input - structure with data to be signed and keys
     * @param {Date} currentDate - optional parameter to pass custom date
     */
    generateSignature(input: AwsSignatureInputData, currentDate: Date = new Date()): Object {
        if (!input) {
            return {};
        }
        const { canonicalHeaders, dateStamp, amzDate } =
            this.prepareCanonicalHeaders(currentDate, input);
        const { canonicalRequest, signedHeaders } =
            this.prepareCanonicalRequest(input, canonicalHeaders);
        const { stringToSign, algorithm, credentialScope } =
            this.generateStringToSign(dateStamp, input, amzDate, canonicalRequest);
        const signature = this.signString(input, dateStamp, stringToSign);
        const authorizationHeader = this.generateAuthorizationHeader(
            algorithm, input, credentialScope, signedHeaders, signature);

        return {'Content-Type': input.contentType,
                'X-Amz-Date': amzDate,
                'Authorization': authorizationHeader};
    }

    private generateAuthorizationHeader(algorithm: string, input: AwsSignatureInputData,
        credentialScope: string, signedHeaders: string, signature: any)
    {
        return algorithm + ' ' + 'Credential=' + input.accessKey + '/'
            + credentialScope + ', ' + 'SignedHeaders=' + signedHeaders
            + ', ' + 'Signature=' + signature;
    }

    private signString(input: AwsSignatureInputData, dateStamp: string, stringToSign: string) {
        const signingKey = this.getSignatureKey(input.secretKey, dateStamp, input.region, input.service);
        const signature = CryptoJS.HmacSHA256(stringToSign, signingKey).toString();

        return signature;
    }

    private generateStringToSign(dateStamp: string, input: AwsSignatureInputData, amzDate: string,
        canonicalRequest: string)
    {
        const algorithm = 'AWS4-HMAC-SHA256';
        const credentialScope = dateStamp + '/' + input.region + '/'
            + input.service + '/' + 'aws4_request';
        const stringToSign = algorithm + '\n' + amzDate + '\n' + credentialScope +
            '\n' + CryptoJS.SHA256(canonicalRequest).toString();

        return { stringToSign, algorithm, credentialScope };
    }

    private prepareCanonicalRequest(input: AwsSignatureInputData, canonicalHeaders: string) {
        const signedHeaders = 'content-type;host;x-amz-date';
        const payloadHash = CryptoJS.SHA256(input.requestParameters).toString();
        const canonicalRequest = input.method + '\n' + input.canonicalUri + '\n'
            + input.canonicalQuerystring + '\n' + canonicalHeaders + '\n'
            + signedHeaders + '\n' + payloadHash;

        return { canonicalRequest, signedHeaders };
    }

    private prepareCanonicalHeaders(currentDate: Date, input: AwsSignatureInputData) {
        const amzDate = currentDate.toISOString().replace(/-|:|\..{3}/g, '');
        const dateStamp = amzDate.substr(0, 8);
        const canonicalHeaders = 'content-type:' + input.contentType + '\n' + 'host:'
            + input.host + '\n' + 'x-amz-date:' + amzDate + '\n';

        return { canonicalHeaders, dateStamp, amzDate };
    }

    private getSignatureKey(
        key: string,
        dateStamp: string,
        regionName: string,
        serviceName: string): any
    {
        const kDate = CryptoJS.HmacSHA256(dateStamp, "AWS4" + key);
        const kRegion = CryptoJS.HmacSHA256(regionName, kDate);
        const kService = CryptoJS.HmacSHA256(serviceName, kRegion);
        const kSigning = CryptoJS.HmacSHA256("aws4_request", kService);

        return kSigning;
    }
}
