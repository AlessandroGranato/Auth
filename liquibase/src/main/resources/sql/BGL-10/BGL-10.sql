insert into auth.auth_resources(resource_path) values('/bds/api/users/user-identifier/*');

insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/users/user-identifier/*'), 1);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/users/user-identifier/*'), 2);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/users/user-identifier/*'), 3);

insert into auth.auth_resources(resource_path) values('/bds/api/temperatures/device/*');

insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/temperatures/device/*'), 1);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/temperatures/device/*'), 2);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/temperatures/device/*'), 3);