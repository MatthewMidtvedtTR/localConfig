/*
 * This rule runs when a federated user logs in, to either auto-provision and auto-link
 * to a local account, if one didn't exist already. If there is a local account with the same email address, this rule redirects to an
 * account linking UI, and also handles redirect callback to link the federated account.
 * Local account will be treated as the primary account for linking.
 */
function (user, context, callback) {

    const clientName = context.clientName;
    let localUserAccount = {};
    let nonIDPRolesToAssign = [];
    let uuid = require("uuid");
    let linkingStrategy = ""; //Can be either of jit / authTimeLink / autoMapping
    const redirectUrl = configuration.ACCOUNT_LINKING_REDIRECT_URL;
  
    let ManagementClient = require('auth0@2.23.0').ManagementClient;
    const management = new ManagementClient({
        domain: auth0.domain,
        clientId: configuration.CLIENT_ID,
        clientSecret: configuration.CLIENT_SECRET
    });

    function errorCallBack(err) {
        logError(err);
        callback(new UnauthorizedError(err));
    }

    function successCallback(_) {
        callback(null, user, context);
        return _;
    }

    /**
     * Returns true if the account is federated, false otherwise
     * @param account
     * @returns {boolean|boolean}
     */
    function isFederatedAccount(account) {
        const result =  account.connection !== "Username-Password-Authentication" &&
            account.federated_provider_id !== undefined &&
            account.federated_user_id !== undefined;
        debug("Is the account " + account.user_id + " federated? :" + result);
        return result;
    }

    /**
     * Returns if the input account is local.
     * @param account
     * @returns {boolean}
     */
    function isLocalAccount(account) {
        return !isFederatedAccount(account);
    }

    /**
     * Returns a JSON that adds ownership and linked_data information to the existing metadata.
     * @param account
     * @returns {{}}
     */
    function createAppMetadataReq(account) {
        const localAccountAppMetadata = account.app_metadata || {};
        localAccountAppMetadata.owning_entity = {};
        localAccountAppMetadata.owning_entity.entity_type = 'customer';
        localAccountAppMetadata.owning_entity.customer_id = user.federated_provider_id;

        const linked_data_array = localAccountAppMetadata.linked_data || [];

        const currentFederatedAccountLinkedData = {};
        currentFederatedAccountLinkedData.sub = user.user_id;
        if(user.app_metadata && user.app_metadata.euid) {
            currentFederatedAccountLinkedData.euid = user.app_metadata.euid;
        }
        linked_data_array.push(currentFederatedAccountLinkedData);
        localAccountAppMetadata.linked_data = linked_data_array;

        return localAccountAppMetadata;
    }

    /**
     * The following "if" block links the local account to federated account, after the redirect callback from digital UI
     * where user authenticated using the local account.
     */
    if (context.protocol === "redirect-callback" && isFederatedAccount(user)) {
        debug("Inside redirect callback");
        searchWithSameEmailAddress()
            .then(function (userSeachResults) {
                return userSeachResults.filter(function (userSearchResult) {
                    /**
                     * The account to be linked to should satisfy following conditions:
                     * a. Should be a local account, and must not already be linked
                     * b. Should have "link" attribute in app_metadata, value set to true
                     *      - this attribute is set from Digital UI once user proves ownership
                     * c. Should have email verified.
                     */
                    return user.user_id !== userSearchResult.user_id &&
                        isLocalAccount(userSearchResult) && !isLinkedAccount(userSearchResult) &&
                        userSearchResult.app_metadata.link && userSearchResult.app_metadata.link === 'true' &&
                        userSearchResult.email_verified === true;
                });
            }).then(function (searchResult) {
            if(searchResult.length === 0) {
                return Promise.reject("No suitable local account found to link");
            }
            debug('Local account to be linked to: ' + JSON.stringify(searchResult[0]));
            localUserAccount = searchResult[0];
            const localAccountAppMetadata = createAppMetadataReq(searchResult[0]);
            return auth0.users.updateAppMetadata(searchResult[0].user_id, localAccountAppMetadata);
        }).then(linkAccount)
            .then(assignNonIDPRoles)
            .then(successCallback)
            .catch(errorCallBack);
    } else {
        /**
         * If the current authentication is done using username-password connection, or, if the user is trying to link the accounts
         * from Account Linking UI, this rule is bypassed.
         */
        if (context.connection !== configuration.PING_CONNECTION || isSilentAuthCallFromAccountLinkingUI()) {
            debug("Not federation connection or, the user is currently linking the accounts. Skipping rule");
            return callback(null, user, context);
        } else if (user.email) {
            /**
             * If user logged in via federation, but, if the domain isn't reserved, this rule is bypassed.
             */
            let emailParts = user.email.split('@');
            if (!(context.connectionOptions && context.connectionOptions.domain_aliases &&
                context.connectionOptions.domain_aliases.includes(emailParts[emailParts.length - 1]))) {
                debug("User logged in via federation, but the domain isn't reserved");
                return callback(null, user, context);
            }
        } else {
            logError("User logged in via federation, but there isn't an email address on the profile");
            return callback(new UnauthorizedError("Invalid profile received from upstream IDP: Missing email address"));
        }
        if (!isLinkedAccount(user)) {
            createLinkingStrategy()
                .then(function (linkingStrategy) {
                    switch (linkingStrategy) {
                        case 'jit' :
                            return provisionLocalAccount()
                                .then(linkAccount)
                                .then(assignNonIDPRoles)
                                .then(successCallback)
                                .catch(errorCallBack);
                        case 'autoMapping' :
                            return populateLinkedData()
                                .then(linkAccount)
                                .then(assignNonIDPRoles)
                                .then(successCallback)
                                .catch(errorCallBack);
                        case 'authTimeLink' :
                            context.redirect = {
                                url: redirectUrl
                            };
                            context.isAccountLinkingRedirect = true;
                            return callback(null, user, context);
                        case 'localAccountPreviouslyLinked' :
                            logError('A local account exists with the same email address, but it is already linked to a different federated account');
                            return errorCallBack('No suitable local account found to link');
                    }
                });
        } else {
            return callback(null, user, context);
        }
    }
    /**
     * Creates a linking strategy based on the state of corresponding local account
     * If mapping attributes present in the local/provisioned account then it should matched with the fed account attributes
     * @returns {string}
     */
    function createLinkingStrategy() {
        return new Promise(function (resolve, reject) {
            searchWithSameEmailAddress()
                .then(function (userSeachResults) {
                    return userSeachResults.filter(function (userSearchResult) {
                        return user.user_id !== userSearchResult.user_id && !isFederatedAccount(userSearchResult);
                    });
                }).then(function (searchResult) {
                if (searchResult && searchResult.length > 0) {
                    localUserAccount = searchResult[0];
                    if (isLinkedAccount(searchResult[0])) {
                        linkingStrategy = "localAccountPreviouslyLinked";
                    } else  {
                        if(localUserAccount.app_metadata !== undefined && localUserAccount.app_metadata.federated_mapping_attributes !== undefined) {
                            if(localUserAccount.app_metadata.federated_mapping_attributes.federated_user_id !== undefined && localUserAccount.app_metadata.federated_mapping_attributes.federated_provider_id !== undefined){
                                if(user.federated_user_id === localUserAccount.app_metadata.federated_mapping_attributes.federated_user_id && user.federated_provider_id === localUserAccount.app_metadata.federated_mapping_attributes.federated_provider_id){
                                    linkingStrategy = 'autoMapping';
                                }else{
                                    return errorCallBack('Error in mapping attributes');
                                }
                            }else{
                                linkingStrategy = 'authTimeLink';
                            }
                        } else {
                            /**
                             * If mapping attributes don't exist, continue to authenticate using local account
                             */
                            linkingStrategy = 'authTimeLink';
                        }
                    }
                }
                else {
                    linkingStrategy = 'jit';
                }
                debug('Linking Strategy: ' + linkingStrategy);
                return resolve(linkingStrategy);
            });
        });
    }

    /**
     * Account Linking UI can initiate a silent authentication call following a redirect to the UI from this rule.
     * If the current context is created for this silent authentication from Account Linking UI, a new redirect shouldn't happen.
     * @returns {boolean}
     */
    function isSilentAuthCallFromAccountLinkingUI() {
        const isSilentAuthCall =  context.clientMetadata !== undefined && context.clientMetadata.allow_federated_account_silent_auth_for_account_linking &&
            context.clientMetadata.allow_federated_account_silent_auth_for_account_linking.toLowerCase() === 'true' &&
            isFederatedAccount(user)  && context.request && context.request.query !== undefined &&
            context.request.query.hint === 'account-linking-bypass';
        debug("Is this a silent auth call for account linking? " + isSilentAuthCall);
        if(isSilentAuthCall) {
            context.isSilentAuthCall = true;
            context.isAccountLinkingRedirect = true;
        }
        return isSilentAuthCall;
    }

    /**
     * Returns a boolean value indicating if the input account is already linked to a local account.
     * @param account
     * @returns {boolean}
     */
    function isLinkedAccount(account) {
        const hasMultipleIdentities = account.identities && account.identities.length > 1;
        let result = false;
        if (hasMultipleIdentities) {
            account.identities.forEach(identity => {
                if (identity.connection === "Username-Password-Authentication") { // Local account found
                    result = true;
                }
            });
        }
        debug("Is the account " + account.user_id + " already linked to a local account?: " + result);
        return result;
    }

    /**
     * Returns a Promise that resolves to email accounts with the same email address.
     * @returns {PromiseLike<T>}
     */
    function searchWithSameEmailAddress() {
        return management.getUsersByEmail(user.email);
    }

    /**
     * After a local account is provisioned, any non-idp roles needs to be assigned to the local account.
     * Assignment of the IDP roles will be done in "Assign Required Roles" rule.
     * @returns {undefined}
     */
    function assignNonIDPRoles() {
        let userRoles = context.authorization.roles;
        nonIDPRolesToAssign = userRoles.filter(role => !role.endsWith('_idp_all'));
        const userIdParam = { id : localUserAccount.user_id};

        debug('Following non-idp roles will be assigned to the new profile: '+nonIDPRolesToAssign);
        if (nonIDPRolesToAssign.length > 0) {
            let roleIDPromises = [];
            let roleIDsToAssign = [];
            //For each of the role names in current context object, the following logic spawns calls to get the role-id.
            //Auth0's management client returns a Promise [if no callbacks are being used], the reference of which is
            // being stored in an array.
            nonIDPRolesToAssign.map(roleName => {
                roleIDPromises.push(
                    management.getRoles({name_filter: roleName}));
            });
            //Promise.all is used to wait for the child Promises to return, and the iterable result is available in corresponding
            // 'then' clause. We extract the role-ids from the iterable result so that all these roles can be assigned in one shot.
            return Promise.all(roleIDPromises)
                .then(roles => {
                    roles.map(role => {
                        roleIDsToAssign.push(role[0].id);
                    });
                })
                .then(() => {
                    management.assignRolestoUser(userIdParam, {"roles": roleIDsToAssign});
                }).then(() => {
                    // The roles assigned to local account should be mapped in the context object.
                    context.authorization.roles = nonIDPRolesToAssign;
                }).catch(err => {
                    logError("Unexpected error while assigning roles to linked account: " + err);
                    Promise.reject("Unexpected error while assigning roles to linked account: " + err);
                });
        } else {
            return Promise.resolve("There are no non-idp roles to be assigned");
        }
    }

    /**
     * Provisions a local account.
     */
    function provisionLocalAccount() {
        let createUserReq = {};
        createUserReq.connection = "Username-Password-Authentication";
        createUserReq.email =  user.email;
        createUserReq.email_verified = false;
        createUserReq.verify_email = false;
        createUserReq.given_name = user.given_name;
        createUserReq.family_name = user.family_name;
        createUserReq.password = generatePassword();

        let appMetadataReq = createAppMetadataReq(user);

        appMetadataReq.euid = (user.app_metadata && user.app_metadata.euid !== undefined) ? user.app_metadata.euid : uuid();
        appMetadataReq.fulfillmentSource = "JIT";

        createUserReq.app_metadata = appMetadataReq;

        return management.createUser(createUserReq)
            .then(function(createdUser) {
                debug("Created user successfully");
                localUserAccount = createdUser;
            })
            .catch(function(err) {
                return Promise.reject("Unexpected error while provisioning and linking account: "+err);
            });
    }

    /**
     * Links federated account to the local account
     * @returns {Promise<unknown>}
     */
    function linkAccount() {
        return new Promise(function(resolve, reject) {
            let linkUserReq = {};
            linkUserReq.user_id = user.user_id;
            linkUserReq.connection_id = configuration.PING_CONNECTION_ID;
            linkUserReq.provider = "oidc";

            management.linkUsers(localUserAccount.user_id, linkUserReq)
                .then(linkResult => {
                    localUserAccount.identities = linkResult;
                    user = localUserAccount;
                    context.primaryUser = localUserAccount.user_id;
                    if (context.protocol === "redirect-callback") {
                        // If the accounts are being linked after a redirect-callback, (Forced-Linking scenario), the context.connection parameter is set to UPA connection.
                        // In this case, the "Assign Required Roles" rule gets bypassed and _idp_all roles are not assigned.
                        // The following adds a variable to context object so that _idp_all roles are assigned in the "Assign Required Roles" rule.
                        context.assignIDPRole = true;
                    }
                    return resolve("Account linked to the federated user");
                }).catch(err => {
                logError("Unexpected error while linking federated account to the local account: "+err);
                reject("Unexpected error while linking federated account to the local account: "+err);
            });
        });
    }

    /**
     * Updates local account metadata with the "linked_data" attribute
     * @returns Promise
     */
    function populateLinkedData() {
        const updatedAppMetadata = createAppMetadataReq(localUserAccount);
        return auth0.users.updateAppMetadata(localUserAccount.user_id, updatedAppMetadata);
    }

    function debug(statement) {
        if (configuration.CONSOLE_LOGS_ENABLED === 'true') {
            console.log('[Account Linking : ' + clientName + ',and user: ' + user.user_id + ']: ' + statement);
        }
    }
    function logError(statement) {
        console.error('ERROR: [Account Linking : ' + clientName + ',and user: ' + user.user_id + ']: ' + statement);
    }

    /**
     * Generates a random password for JIT local user creation. 
     * Generates UUID and randomly inserts a special character + uppercase character
     * Returns UUID with one random special character and one random upper character
     */
     function generatePassword() {
        var inituuid = uuid();
        var specialChars = "!@#$%^&*";
        var upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        var randSpecialChar = specialChars.charAt(Math.floor(Math.random() * (specialChars.length - 1)));
        var randUpperChar = upperChars.charAt(Math.floor(Math.random() * (upperChars.length - 1)));
        var insertIndex = Math.floor(Math.random() * (inituuid.length - 1));
        var finalString = inituuid.slice(0, insertIndex) + randSpecialChar + randUpperChar + inituuid.slice(insertIndex);
        return finalString;
      }
}
