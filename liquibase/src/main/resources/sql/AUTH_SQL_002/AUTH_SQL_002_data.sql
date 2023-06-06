insert into auth.auth_resources(resource_path) values('/auth/api/test/user');
insert into auth.auth_resources(resource_path) values('/auth/api/test/mod');
insert into auth.auth_resources(resource_path) values('/auth/api/test/admin');

insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/auth/api/test/user'), 1);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/auth/api/test/user'), 2);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/auth/api/test/user'), 3);

insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/auth/api/test/mod'), 2);
insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/auth/api/test/mod'), 3);

insert into auth.auth_resources_roles(resource_id, auth_role_id) values((select s.id from auth.auth_resources s where s.resource_path = '/auth/api/test/admin'), 3);
