const config = {
    // Router panel URL
    adminUrl: 'http://192.168.8.1/',
    // Router admin username
    adminUser: 'admin',
    // Router admin password
    adminPass: 'password'
};

const axios = require('axios');
const CryptoJS = require('crypto-js');

let instance = axios.create({
    baseURL: config.adminUrl,
    withCredentials: true
});

async function getServerToken(cookie) {
    let response = await instance.get('api/webserver/token', {
        headers: {
            'Cookie': cookie
        }
    });
    return response.data.match('\<token\>(.*)\<\/token\>')[1].substr(32);
}

async function customPost(url, data, cookie, token) {
    return await instance.post(url, data, {
        headers: {
            'Cookie': cookie,
            '_ResponseSource': 'Browser',
            '__RequestVerificationToken': token,
        }
    });
}

async function getIP() {
    let attempt = 10;
    let response = null;
    try {
        response = await axios.get('https://api.ipify.org');
    } catch(e) {}
    while(response == null && attempt > 0) {
        attempt -= 1;
        await new Promise(r => setTimeout(r, 3000));
        try {
            response = await axios.get('https://api.ipify.org');
        } catch(e) {}    
    }
    if(response != null) {
        return response.data;
    }
    else {
        throw 'Couldn\'t fetch the IP Address';
    }
}

function xmlMatch(data, tag) {
    return data.match('\<' + tag + '\>(.*)\<\/' + tag + '\>')[1];
}

(async () => {
    let cookie = await instance.get('/');
    cookie = cookie.headers['set-cookie'][0];
    let token = await getServerToken(cookie);
    let nonce = Array.from(Array(16), () => Math.floor(Math.random() * 36).toString(36)).map(e => e.charCodeAt(0).toString(16)).join('');
    let postData = `<?xml version="1.0" encoding="UTF-8"?><request><username>${config.adminUser}</username><firstnonce>${nonce}</firstnonce><mode>1</mode></request>`;
    response = await customPost('api/user/challenge_login', postData, cookie, token);
    token = response.headers['__requestverificationtoken'];
    let salt = xmlMatch(response.data, 'salt');
    let iter = xmlMatch(response.data, 'iterations');
    let finalNonce = xmlMatch(response.data, 'servernonce');

    salt = CryptoJS.enc.Hex.parse(salt);

    let authMsg = [nonce, finalNonce, finalNonce].join(',');

    let saltedPassword = CryptoJS.PBKDF2(config.adminPass, salt, {
        keySize: 8,
        iterations: iter,
        hasher: CryptoJS.algo.SHA256
    });

    let clientKey = CryptoJS.HmacSHA256(saltedPassword, 'Client Key');

    let storedKey = CryptoJS.algo.SHA256.create();
    storedKey.update(clientKey);
    storedKey = storedKey.finalize();

    let clientSign = CryptoJS.HmacSHA256(storedKey, authMsg);

    for (let i = 0; i < clientKey.sigBytes / 4; i += 1) {
        clientKey.words[i] = clientKey.words[i] ^ clientSign.words[i]
    }

    let clientProof = clientKey.toString();

    postData = `<?xml version="1.0" encoding="UTF-8"?><request><clientproof>${clientProof}</clientproof><finalnonce>${finalNonce}</finalnonce></request>`;
    response = await customPost('api/user/authentication_login', postData, cookie, token);

    cookie = typeof response.headers['set-cookie'] !== 'undefined' ? response.headers['set-cookie'][0] : '';

    response = await instance.get('api/user/state-login', {
        headers: {
            'Cookie': cookie,
            '_ResponseSource': 'Browser'
        }
    });

    let username = '';

    if (response.data.includes('Username')) {
        username = xmlMatch(response.data, 'Username');
    }
    else {
        username = xmlMatch(response.data, 'username');
    }

    if (username.length > 0) {
        console.log('> Login successful!');
        console.log('> Current IP Address: ' + await getIP());

        postData = '<?xml version="1.0" encoding="UTF-8"?><request><dataswitch>0</dataswitch></request>';
        token = await getServerToken(cookie);
        response = await customPost('api/dialup/mobile-dataswitch', postData, cookie, token);

        if (xmlMatch(response.data, 'response') == 'OK') {
            console.log('> Mobile data disabled!');

            postData = '<?xml version="1.0" encoding="UTF-8"?><request><dataswitch>1</dataswitch></request>';
            token = await getServerToken(cookie);
            response = await customPost('api/dialup/mobile-dataswitch', postData, cookie, token);

            if (xmlMatch(response.data, 'response') == 'OK') {
                console.log('> Mobile data enabled!');

                postData = '<?xml version="1.0" encoding="UTF-8"?><request><Logout>1</Logout></request>';
                token = await getServerToken(cookie);
                response = await customPost('api/user/logout', postData, cookie, token);

                console.log('> New IP Address: ' + await getIP());
                if (xmlMatch(response.data, 'response') == 'OK') {
                    console.log('> Logout successful!');
                }

            }
            else {
                console.log('> Couldn\'t enable the mobile data!')
            }
        }
        else {
            console.log('> Couldn\'t disable the mobile data!');
        }
    }
    else {
        console.log('> Login failed!');
    }

})();
