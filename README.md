# Access Control utility package

## Current version contains only single type of access control - Role Based Access Control (rbac)

### RBAC
You may want for an account to have permission to ban users from a system, but not create new tokens. Role-Based Access Control (RBAC) offers flexibility in this regard.

Module that allows other modules to implement role-based access control mechanisms. This is a lightweight version.

In essence, you will be defining multiple roles, each allowed to perform different sets of actions in your module. 
An account may have, for example, 'moderator', 'minter' or 'admin' roles, which you will then check inside your logic. Separately, you will be able to define rules for how accounts can be granted a role, have it revoked, and more...
Or you can define (optionally) some role which automically become invalid (for all assigned participants) after some period and no need to worry to revoke granted permissions explicitly

```move
 use access_control::rbac;

 struct ModeratorRole {} // 1st role
 struct BridgeRole {}  // second role

 fun init_module(deployer: &signer) {
     // register new roles 
     let (manage_moderator_cap, remove_moderator_cap) = register_role<ModeratorRole>(deployer); // define manager role
     let (manage_bridge_cap, remove_bridge_cap) = register_role<BridgeRole>(deployer); // define bridge role

     // also you have to store capabilities in the global store
     // capabilities required to grant role to new participants or revoke the role   
     ...
 }

 /// grant the roles according to your model. Apparantly you can apply `only owner` for that function or register an admin role in the init_module, grant the role and then check assert_has_role<Admin> inside the function. A lot of options
 public fun grant_role(to:addresss) {
      grant_role<ModeratorRole>(to, &manage_moderator_cap); // capability should be taken from the global store
      grant_role<BridgeRole>(to, &manage_bridge_cap);  // capability should be taken from the global store  
 }


 /// some function to protect the access
 public fun some_func_for_moderator(account:&signer) {
      assert_has_role<Role_A>(user1); // throw the error is role is expired, or role is not granted to the user
      // main code of the function
 }
 ```