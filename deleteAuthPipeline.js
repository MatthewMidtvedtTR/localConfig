const token = process.argv[2];
const strat = process.argv[3];
const domain = 'https://' + process.argv[4];
const axios = require('axios');

if(strat === 'actions') {
    removeActionsFromPostLoginBinding().then(() => getAllDeployedActions()
    .then(response => deleteDeployedActions(response.data.actions))).catch(error=> console.log(error));
} else if(strat === 'rules') {
    getAllDeployedRules().then(response => deleteDeployedRules(response.data)).catch(error=> console.log(error));
    getAllDeployedHooks().then(response => deleteDeployedHooks(response.data)).catch(error=> console.log(error));
}


function getAllDeployedRules() {
    let config = {
        method: 'get',
        maxBodyLength: Infinity,
        url: domain + '/api/v2/rules?fields=id%2Cenabled%2Cname&include_fields=true',
        headers: {
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + token
        }
    };
    return axios.request(config);
}

function getAllDeployedActions() {
    let config = {
        method: 'get',
        maxBodyLength: Infinity,
        url: domain + '/api/v2/actions/actions',
        headers: {
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + token
        }
    };

    return axios.request(config);
}

function removeActionsFromPostLoginBinding() {
    let data = JSON.stringify({
        "bindings": []
    });

    let config = {
        method: 'patch',
        maxBodyLength: Infinity,
        url: domain + '/api/v2/actions/triggers/post-login/bindings',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + token
        },
        data : data
    };

    return axios.request(config);
}

function deleteDeployedRules(rules) {
    rules.forEach(rule => {
        let config = {
            method: 'delete',
            maxBodyLength: Infinity,
            url: domain + '/api/v2/rules/' + rule.id,
            headers: {
                'Authorization': 'Bearer ' + token
            }
        };

        axios.request(config)
            .then(() => {
                console.log(rule.name + ' with ID ' + rule.id + ' has been deleted');
            })
            .catch((error) => {
                console.log(error.response);
                console.log('intervention by operations is required to correct the issue');
            });
    });
}

function deleteDeployedActions(actions) {
    actions.forEach(action => {
        let config = {
            method: 'delete',
            maxBodyLength: Infinity,
            url: domain + '/api/v2/actions/actions/' + action.id,
            headers: {
                'Authorization': 'Bearer ' + token
            }
        };

        axios.request(config)
            .then(() => {
                console.log(action.name + ' with ID ' + action.id + ' has been deleted');
            })
            .catch((error) => {
                console.log(error.response.data); //this should be all the information that we need.
                console.log('intervention by operations is required to correct the issue');
            });
    });
}

function getAllDeployedHooks() {
    let config = {
        method: 'get',
        maxBodyLength: Infinity,
        url: domain + '/api/v2/hooks',
        headers: {
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + token
        }
    };

    return axios.request(config)
}

function deleteDeployedHooks(hooks) {
    hooks.forEach(hook => {
        let config = {
            method: 'delete',
            maxBodyLength: Infinity,
            url: domain + '/api/v2/hooks/' + hook.id,
            headers: {
                'Authorization': 'Bearer ' + token
            }
        };

        axios.request(config)
            .then((response) => {
                console.log(response);
                console.log('hook was successfully removed');
            })
            .catch((error) => {
                console.log(error);
            });
    });
}