/// Role based access control module
/// The main idea described below
/// 1. Module register any role and receives two capabilities to manage roles (ManageCapability<RoleId>, RemoveCapability<RoleId>)
/// 2. Module can grant / revoke the role to any user.
/// 3. Module is able to define the TTL for the new role. This field is immutable. If time is elapsed, then role is not longer valid
/// 4. Module can utilize assert_has_role inside the code to prevent not authorized access to any function
/// 5. If module wants to destroy the management capability -- it is possible
module access_control::rbac {
    
    use aptos_std::signer;
    use aptos_std::error;
    use aptos_std::smart_table::{Self, SmartTable};
    use aptos_std::type_info;

    use supra_framework::account;
    use supra_framework::timestamp;
    use supra_framework::event::{Self, EventHandle};


    /// Access deniend
    const EROLE_ID_ACCESS_DENIED: u64 = 1;
    /// Access deniend, role is expired
    const EROLE_ID_ROLE_EXPIRED: u64 = 2;
    /// Address of account which is used to initialize a new Role doesn't match the deployer of module
    const EROLE_ID_ADDRESS_MISMATCH: u64 = 3;
    /// `RoleId` is already registered
    const EROLE_ID_ALREADY_REGISTERED: u64 = 4;
    /// `RoleId` is not registered
    const EROLE_ID_NOT_REGISTERED: u64 = 5;
    /// TTL is not valid
    const EROLE_TTL_PAST: u64 = 6;
    /// Role already granted
    const EROLE_ALREADY_GRANTED: u64 = 7;
    /// Role not granted yet
    const EROLE_NOT_GRANTED: u64 = 8;    
    /// Role already revoked
    const EROLE_ALREADY_REVOKED: u64 = 9;

    struct RoleStore<phantom RoleId> has key {
        expired: u64, // when role is no longer valid, default is 0, immutable after registration
        has_role: SmartTable<address, bool>,
        grant_events: EventHandle<GrantRole>,
        revoke_events: EventHandle<RevokeRole>,
    }

    /// Capability required to manage (grant/revoke) role
    struct ManageCapability<phantom RoleId> has copy, store {}

    /// Capability to destroy role entire entity
    struct RemoveCapability<phantom RoleId> has copy, store {}

    #[event]
    struct GrantRole has drop, store {
        account: address,
    }

    #[event]
    struct RevokeRole has drop, store {
        account: address,
    }    

    /// Register a new role
    public fun register_role<RoleId>(account: &signer): (ManageCapability<RoleId>, RemoveCapability<RoleId>) {
        register_role_internal(account, 0)
    }

    // Register a new role with some expired time.
    public fun register_role_with_ttl<RoleId>(account: &signer, ttl:u64): (ManageCapability<RoleId>, RemoveCapability<RoleId>) {
        register_role_internal(account, ttl)
    }    

    /// Remove role
    public fun remove_role<RoleId>(cap:RemoveCapability<RoleId>) acquires RoleStore {
        let r_address = role_address<RoleId>();
        assert!(exists<RoleStore<RoleId>>(r_address), error::not_found(EROLE_ID_NOT_REGISTERED));
        let RoleStore<RoleId> {expired:_, has_role, grant_events, revoke_events} = move_from<RoleStore<RoleId>>(r_address);
        smart_table::destroy(has_role);
        event::destroy_handle(grant_events);
        event::destroy_handle(revoke_events);

        let RemoveCapability {} = cap;
    }

    ///Grant an existing role from the user. If role has been already granted error is thrown
    public fun grant_role<RoleId>(to: address, _cap: &ManageCapability<RoleId>) acquires RoleStore {
        grant_role_internal<RoleId>(to, true);
    }

    /// Revoke an existing role from the user. If role hasn't been granted yet error is thrown
    public fun revoke_role<RoleId>(to: address, _cap: &ManageCapability<RoleId>) acquires RoleStore {
        grant_role_internal<RoleId>(to, false);
    }    

    /// Destroy a manage capability.
    public fun destroy_manage_cap<RoleId>(manage_cap: ManageCapability<RoleId>) {
        let ManageCapability<RoleId> {} = manage_cap;
    }

    /// Destroy a remove capability.
    public fun destroy_remove_cap<RoleId>(remove_cap: RemoveCapability<RoleId>) {
        let RemoveCapability<RoleId> {} = remove_cap;
    }

    /// Asserts if role is not registered or expired or user hasn't been granted yet
    public fun assert_has_role<RoleId>(account:address) acquires RoleStore {
        let r_address = role_address<RoleId>();
        assert!(exists<RoleStore<RoleId>>(r_address),error::not_found(EROLE_ID_NOT_REGISTERED));
        let role = borrow_global<RoleStore<RoleId>>(r_address);
        if (role.expired > 0) {
            // check expired
            assert!(role.expired > timestamp::now_seconds(), error::permission_denied(EROLE_ID_ROLE_EXPIRED));
        };
        let has_role = *smart_table::borrow_with_default(&role.has_role, account, &false);
        assert!(has_role, error::permission_denied(EROLE_ID_ACCESS_DENIED));
    }

    /// Checks if the role is registered and not expired and user has been granted by this role
    public fun has_role<RoleId>(account:address): bool acquires RoleStore {
        let r_address = role_address<RoleId>();
        if (!exists<RoleStore<RoleId>>(r_address)) return false;
        let role = borrow_global<RoleStore<RoleId>>(r_address);
        if (role.expired > 0) {
            // check ttl
            if (timestamp::now_seconds() > role.expired) return false;
        };
        let has_role = *smart_table::borrow_with_default(&role.has_role, account, &false);
        return has_role
    }    

    fun grant_role_internal<RoleId> (to: address, grant : bool) acquires RoleStore {
        let r_address = role_address<RoleId>();
        assert!(exists<RoleStore<RoleId>>(r_address),error::not_found(EROLE_ID_NOT_REGISTERED));
        let role = borrow_global_mut<RoleStore<RoleId>>(r_address);

        if (role.expired > 0) {
            // check ttl
            assert!(role.expired > timestamp::now_seconds() , error::permission_denied(EROLE_ID_ROLE_EXPIRED));
        };

        if (!smart_table::contains(&mut role.has_role, to)) {
            if (grant) {
                smart_table::add(&mut role.has_role, to, true); // grant
            } else {
                // revoke
                abort error::not_found(EROLE_NOT_GRANTED) // not granted yet
            };
        } else {
            // record available
            let exst = smart_table::borrow_mut(&mut role.has_role, to);
            if (grant) {
                assert!(!*exst, error::not_found(EROLE_ALREADY_GRANTED)); // already granted
            } else {
                //revoke
                assert!(*exst, error::not_found(EROLE_ALREADY_REVOKED));
            };                
            *exst = grant;
        };

        if (grant) {
            event::emit_event<GrantRole>(&mut role.grant_events, GrantRole { account: to },);
        }else {
            event::emit_event<RevokeRole>(&mut role.revoke_events, RevokeRole { account: to },);
        }
        
    }

    #[view]
    /// Returns true if the RoleId is already registered
    public fun is_role_registered<RoleId>(): bool {
        exists<RoleStore<RoleId>>(role_address<RoleId>())
    }

    #[view]
    /// Returns true if the RoleId is already registered and ttl is either 0 or greather than current time
    public fun is_role_alive<RoleId>(): bool acquires RoleStore {
        if (!is_role_registered<RoleId>()) {
            return false
        };

        let role = safe_role_store<RoleId>();
        if (role.expired > 0) {
            (role.expired > timestamp::now_seconds())
        } else true
    }         

    inline fun safe_role_store<RoleId>(): &RoleStore<RoleId> acquires RoleStore {
        borrow_global<RoleStore<RoleId>>(role_address<RoleId>())
    }

    fun role_address<RoleId>(): address {
        let type_info = type_info::type_of<RoleId>();
        type_info::account_address(&type_info)
    }

    fun register_role_internal<RoleId>(account: &signer, ttl: u64): (ManageCapability<RoleId>, RemoveCapability<RoleId>) {
        let account_addr = signer::address_of(account);

        assert!(role_address<RoleId>() == account_addr, error::invalid_argument(EROLE_ID_ADDRESS_MISMATCH));
        assert!(!exists<RoleStore<RoleId>>(account_addr),error::already_exists(EROLE_ID_ALREADY_REGISTERED));
        let expired = if (ttl > 0) {
            // if ttl is set then it must be a future time
            assert!(timestamp::now_seconds() > ttl, error::invalid_argument(EROLE_TTL_PAST));
            timestamp::now_seconds() + ttl
        } else {
            0
        };

        let role_store = RoleStore<RoleId> {
            expired : expired,
            has_role: smart_table::new(),
            grant_events: account::new_event_handle<GrantRole>(account),
            revoke_events: account::new_event_handle<RevokeRole>(account),
        };

        move_to(account, role_store);       
        (ManageCapability<RoleId> {}, RemoveCapability<RoleId> {})
    }


    #[test_only]
    struct Role_A {}
    #[test_only]
    struct Role_B {}    

    #[test(deployer = @access_control, user1 = @0x987, user2 = @0x876)]
    fun test_register_role(deployer: &signer, user1 : address, user2 : address) acquires RoleStore{
        let deployer_addr = signer::address_of(deployer);
        account::create_account_for_test(deployer_addr);
        let (manage_cap, remove_cap) = register_role<Role_A>(deployer);

        assert!(is_role_registered<Role_A>(), 1);
        assert!(!is_role_registered<Role_B>(), 1); // not registered

        assert!(is_role_alive<Role_A>(), 1);
        assert!(!is_role_alive<Role_B>(), 1);        

        let ManageCapability<Role_A> {} = manage_cap;
        let RemoveCapability<Role_A> {} = remove_cap;
    }

    #[test(deployer = @access_control, user1 = @0x987, user2 = @0x876)]
    fun test_grant_role(deployer: &signer, user1 : address, user2 : address) acquires RoleStore{
        let deployer_addr = signer::address_of(deployer);
        account::create_account_for_test(deployer_addr);
        let (manage_cap_a, remove_cap_a) = register_role<Role_A>(deployer);
        let (manage_cap_b, remove_cap_b) = register_role<Role_B>(deployer);
        grant_role<Role_A>(user1, &manage_cap_a); // grant role A to user1
        grant_role<Role_B>(user2, &manage_cap_b); // grant role B to user2

        assert_has_role<Role_A>(user1);
        assert_has_role<Role_B>(user2);

        let ManageCapability<Role_A> {} = manage_cap_a;
        let RemoveCapability<Role_A> {} = remove_cap_a;

        let ManageCapability<Role_B> {} = manage_cap_b;
        let RemoveCapability<Role_B> {} = remove_cap_b;        
    }

    #[test(deployer = @access_control, user1 = @0x987)]
    fun test_remove(deployer: &signer, user1 : address) acquires RoleStore{
        let deployer_addr = signer::address_of(deployer);
        account::create_account_for_test(deployer_addr);
        let (manage_cap_a, remove_cap_a) = register_role<Role_A>(deployer);
        grant_role<Role_A>(user1, &manage_cap_a); // grant role A to user1

        assert_has_role<Role_A>(user1);
        assert!(has_role<Role_A>(user1), 1);

        remove_role<Role_A>(remove_cap_a);

        let ManageCapability<Role_A> {} = manage_cap_a;
        let RemoveCapability<Role_A> {} = remove_cap_a;
    }


    #[test(deployer = @access_control, user1 = @0x987, user2 = @0x876)]
    fun test_grant_revoke_role(deployer: &signer, user1 : address, user2 : address) acquires RoleStore{
        let deployer_addr = signer::address_of(deployer);
        account::create_account_for_test(deployer_addr);
        let (manage_cap_a, remove_cap_a) = register_role<Role_A>(deployer);
        grant_role<Role_A>(user1, &manage_cap_a); // grant role A to user1
        grant_role<Role_A>(user2, &manage_cap_a); // grant role A to user2

        assert_has_role<Role_A>(user1);
        assert_has_role<Role_A>(user2);

        assert!(has_role<Role_A>(user1), 1);
        assert!(has_role<Role_A>(user2), 1);

        revoke_role<Role_A>(user1, &manage_cap_a);
        revoke_role<Role_A>(user2, &manage_cap_a);
        assert!(!has_role<Role_A>(user1), 1);
        assert!(!has_role<Role_A>(user2), 1);

        let ManageCapability<Role_A> {} = manage_cap_a;
        let RemoveCapability<Role_A> {} = remove_cap_a;

    }

    #[test(supra = @0x1, deployer = @access_control, user1 = @0x987)]
    #[expected_failure(abort_code = 327682, location = Self )] // error::not_found(EROLE_ID_ROLE_EXPIRED)
    fun test_expired_grant(supra : &signer, deployer: &signer, user1 : address) acquires RoleStore{

        let t0 = 100001000000;
        let ttl = 3600;
        timestamp::set_time_has_started_for_testing(supra);
        timestamp::update_global_time_for_test_secs(t0);
        
        let deployer_addr = signer::address_of(deployer);
        account::create_account_for_test(deployer_addr);
        let (manage_cap_a, remove_cap_a) = register_role_with_ttl<Role_A>(deployer, ttl);
        grant_role<Role_A>(user1, &manage_cap_a); // grant role A to user1

        assert_has_role<Role_A>(user1);
        assert!(has_role<Role_A>(user1), 1);

        // move time
        timestamp::fast_forward_seconds(ttl - 5);

        // still ok
        assert_has_role<Role_A>(user1);
        assert!(has_role<Role_A>(user1), 1);

        // move time
        timestamp::fast_forward_seconds(6);
        assert!(!has_role<Role_A>(user1), 1); // expired role

        // again, error because role already expired
        grant_role<Role_A>(user1, &manage_cap_a); 

        let ManageCapability<Role_A> {} = manage_cap_a;
        let RemoveCapability<Role_A> {} = remove_cap_a;
    }     

    #[test(deployer = @access_control, user1 = @0x987)]
    #[expected_failure(abort_code = 393223, location = Self )] // error::not_found(EROLE_ALREADY_GRANTED)
    fun test_already_granted(deployer: &signer, user1 : address) acquires RoleStore{
        let deployer_addr = signer::address_of(deployer);
        account::create_account_for_test(deployer_addr);
        let (manage_cap_a, remove_cap_a) = register_role<Role_A>(deployer);
        grant_role<Role_A>(user1, &manage_cap_a); // grant role A to user1
        // again
        grant_role<Role_A>(user1, &manage_cap_a); // grant role A to user1

        let ManageCapability<Role_A> {} = manage_cap_a;
        let RemoveCapability<Role_A> {} = remove_cap_a;
    } 

    #[test(deployer = @access_control, user1 = @0x987)]
    #[expected_failure(abort_code = 393225, location = Self )] // error::not_found(EROLE_ALREADY_REVOKED)
    fun test_already_revoked(deployer: &signer, user1 : address) acquires RoleStore{
        let deployer_addr = signer::address_of(deployer);
        account::create_account_for_test(deployer_addr);
        let (manage_cap_a, remove_cap_a) = register_role<Role_A>(deployer);
        grant_role<Role_A>(user1, &manage_cap_a); // grant role A to user1

        assert_has_role<Role_A>(user1);
        assert!(has_role<Role_A>(user1), 1);

        revoke_role<Role_A>(user1, &manage_cap_a);
        revoke_role<Role_A>(user1, &manage_cap_a); // not allowed

        let ManageCapability<Role_A> {} = manage_cap_a;
        let RemoveCapability<Role_A> {} = remove_cap_a;

    }

    #[test(deployer = @access_control, user1 = @0x987)]
    #[expected_failure(abort_code = 393224, location = Self )] // error::not_found(EROLE_ALREADY_REVOKED)
    fun test_not_granted_yet(deployer: &signer, user1 : address) acquires RoleStore{
        let deployer_addr = signer::address_of(deployer);
        account::create_account_for_test(deployer_addr);
        let (manage_cap_a, remove_cap_a) = register_role<Role_A>(deployer);

        assert!(!has_role<Role_A>(user1), 1);
        revoke_role<Role_A>(user1, &manage_cap_a); // not allowed

        let ManageCapability<Role_A> {} = manage_cap_a;
        let RemoveCapability<Role_A> {} = remove_cap_a;

    }          

}