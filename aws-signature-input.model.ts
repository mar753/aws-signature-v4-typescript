export class AwsSignatureInputData {
    method: string;
    service: string;
    host: string;
    region: string;
    endpoint: string;
    requestParameters: string = '';
    contentType: string = 'text/plain';
    accessKey: string;
    secretKey: string;
    canonicalUri: string;
    canonicalQuerystring: string = '';
}
