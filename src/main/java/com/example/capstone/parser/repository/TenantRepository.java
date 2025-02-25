package com.example.capstone.parser.repository;

import com.example.capstone.parser.model.TenantEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TenantRepository extends JpaRepository<TenantEntity, Long> {
}
