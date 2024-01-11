insert into auth.auth_resources(resource_path) values('/auth/api/auth/refresh-token');
insert into auth.auth_resources(resource_path) values('/auth/api/auth/authorize-resource');
insert into auth.auth_resources(resource_path) values('/auth/api/auth/*');

insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/auth/api/auth/refresh-token'), 1);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/auth/api/auth/refresh-token'), 2);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/auth/api/auth/refresh-token'), 3);

insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/auth/api/auth/authorize-resource'), 1);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/auth/api/auth/authorize-resource'), 2);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/auth/api/auth/authorize-resource'), 3);

insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/auth/api/auth/*'), 1);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/auth/api/auth/*'), 2);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/auth/api/auth/*'), 3);

insert into auth.auth_resources(resource_path) values('/bds/api/devices/*');
insert into auth.auth_resources(resource_path) values('/bds/api/devices');
insert into auth.auth_resources(resource_path) values('/bds/api/users/*');
insert into auth.auth_resources(resource_path) values('/bds/api/users');
insert into auth.auth_resources(resource_path) values('/bds/api/temperatures/*');
insert into auth.auth_resources(resource_path) values('/bds/api/temperatures');

insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/devices/*'), 1);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/devices/*'), 2);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/devices/*'), 3);

insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/devices'), 1);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/devices'), 2);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/devices'), 3);

insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/users/*'), 1);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/users/*'), 2);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/users/*'), 3);

insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/users'), 1);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/users'), 2);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/users'), 3);

insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/temperatures/*'), 1);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/temperatures/*'), 2);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/temperatures/*'), 3);

insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/temperatures'), 1);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/temperatures'), 2);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/bds/api/temperatures'), 3);


