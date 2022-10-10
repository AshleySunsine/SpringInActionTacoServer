package ru.prob.tacoserver.repository;

import org.springframework.data.repository.CrudRepository;
import ru.prob.tacoserver.model.UserU;

public interface UserRepository extends CrudRepository<UserU, Long> {
    UserU findByUsername(String username);
}
