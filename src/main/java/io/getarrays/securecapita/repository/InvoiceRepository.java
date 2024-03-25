package io.getarrays.securecapita.repository;

import io.getarrays.securecapita.domain.Invoice;
import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface InvoiceRepository
        extends PagingAndSortingRepository<Invoice, Long>, ListCrudRepository<Invoice, Long> {}
