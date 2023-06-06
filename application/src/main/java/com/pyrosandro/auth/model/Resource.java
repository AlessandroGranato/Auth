package com.pyrosandro.auth.model;

import lombok.*;
import org.hibernate.Hibernate;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Entity
@Table(name = "auth_resources")
@Getter
@Setter
@NoArgsConstructor
@RequiredArgsConstructor
@ToString
public class Resource {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @NonNull
    private Long id;

    @NotBlank
    @Size(max = 50)
    private String resourcePath;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "auth_resources_roles",
            joinColumns = @JoinColumn(name = "resource_id"),
            inverseJoinColumns = @JoinColumn(name = "auth_role_id"))
    private Set<Role> roles = new HashSet<>();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || Hibernate.getClass(this) != Hibernate.getClass(o)) return false;
        Resource resource = (Resource) o;
        return id != null && Objects.equals(id, resource.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}