const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const fetch = require('node-fetch');

const generatePolicy = (principalId, resource, effect = 'Allow') => {
  return {
    principalId,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [
        {
          Action: 'execute-api:Invoke',
          Effect: effect,
          Resource: resource,
        },
      ],
    },
  };
};

module.exports.authorizerFunc = async (event, context, cb) => {
  console.log('event: ', event);
  console.log('context: ', context);
  console.log('process.env: ', process.env);

  try {
    const { AWS_REGION, USER_POOL_ID } = process.env;
    const response = await fetch(
      `https://cognito-idp.${AWS_REGION}.amazonaws.com/${USER_POOL_ID}/.well-known/jwks.json`
    );
    const { keys: jwkArr } = await response.json();

    const pem = jwkToPem(jwkArr[0]);
    const token = event.authorizationToken.split(' ')[1];
    const decoded = await promisify(jwt.verify)(token, pem);

    console.log('decoded: ', decoded);

    const groups = decoded['cognito:groups'];
    let policy = generatePolicy(token, event.methodArn);

    if (!groups.find((group) => group === 'admin')) {
      policy = generatePolicy(token, event.methodArn, 'Deny');
    }

    cb(null, policy);
  } catch (err) {
    console.log('error: ', err);

    cb('Unauthorized', err.message);
  }
};

module.exports.hello = async (event) => {
  console.log('event: ', event);

  return {
    statusCode: 200,
    body: JSON.stringify(
      {
        message: 'Go Serverless v1.0! Your function executed successfully!',
        input: event,
      },
      null,
      2
    ),
  };
};
