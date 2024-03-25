package io.getarrays.securecapita.resource;

import io.getarrays.securecapita.domain.Customer;
import io.getarrays.securecapita.domain.HttpResponse;
import io.getarrays.securecapita.domain.Invoice;
import io.getarrays.securecapita.dto.UserDTO;
import io.getarrays.securecapita.service.CustomerService;
import io.getarrays.securecapita.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.Optional;

import static java.time.LocalDateTime.now;
import static java.util.Map.of;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.OK;

@RestController
@RequestMapping(path = "/customer")
@RequiredArgsConstructor
@Slf4j
public class CustomerResource {
    private final CustomerService customerService;
    private final UserService userService;

    @GetMapping("/list")
    public ResponseEntity<HttpResponse> getCustomers (@AuthenticationPrincipal UserDTO user,
                                                      @RequestParam Optional<Integer> page,
                                                      @RequestParam Optional<Integer> size) {
        return ResponseEntity.ok(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .data(of(
                                "user", userService.getUserByEmail(user.getEmail()),
                                "customers", customerService.getCustomers(page.orElse(0), size.orElse(10))))
                        .message("Customers retrieved")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    @PostMapping("/create")
    public ResponseEntity<HttpResponse> createdCustomers (@AuthenticationPrincipal UserDTO user,
                                                         @RequestBody Customer customer) {
        return ResponseEntity.created(URI.create(""))
                .body(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .data(of(
                                "user", userService.getUserByEmail(user.getEmail()),
                                "customer", customerService.createCustomer(customer)))
                        .message("Customer created")
                        .status(CREATED)
                        .statusCode(CREATED.value())
                        .build());
    }

    @GetMapping("/get/{id}")
    public ResponseEntity<HttpResponse> createdCustomer (@AuthenticationPrincipal UserDTO user,
                                                         @PathVariable ("id") Long id) {
        return ResponseEntity.ok(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .data(of(
                                "user", userService.getUserByEmail(user.getEmail()),
                                "customers", customerService.getCustomer(id)))
                        .message("Customer retrieved")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    @GetMapping("/search")
    public ResponseEntity<HttpResponse> searchCustomers (@AuthenticationPrincipal UserDTO user,
                                                        Optional<String> name,
                                                        @RequestParam Optional<Integer> page,
                                                        @RequestParam Optional<Integer> size){
        return ResponseEntity.ok(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .data(of(
                                "user", userService.getUserByEmail(user.getEmail()),
                                "customers", customerService.searchCustomers(name.orElse(""), page.orElse(0), size.orElse(10))))
                        .message("Customers retrieved")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    @PutMapping("/update")
    public ResponseEntity<HttpResponse> updateCustomer (@AuthenticationPrincipal UserDTO user,
                                                        @RequestBody Customer customer){
        return ResponseEntity.ok(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .data(of(
                                "user", userService.getUserByEmail(user.getEmail()),
                                "customer", customerService.updateCustomer(customer)))
                        .message("Customer updated")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    @PostMapping("/invoice/created")
    public ResponseEntity<HttpResponse> createInvoice (@AuthenticationPrincipal UserDTO user,
                                                          @RequestBody Invoice invoice) {
        return ResponseEntity.created(URI.create(""))
                .body(
                        HttpResponse.builder()
                                .timeStamp(now().toString())
                                .data(of(
                                        "user", userService.getUserByEmail(user.getEmail()),
                                        "invoice", customerService.createInvoice(invoice)))
                                .message("Invoice created")
                                .status(CREATED)
                                .statusCode(CREATED.value())
                                .build());
    }

    @PostMapping("/invoice/new")
    public ResponseEntity<HttpResponse> newInvoice (@AuthenticationPrincipal UserDTO user) {
        return ResponseEntity.ok(
                        HttpResponse.builder()
                                .timeStamp(now().toString())
                                .data(of(
                                        "user", userService.getUserByEmail(user.getEmail()),
                                        "customers", customerService.getCustomers()))
                                .message("Customers retrieved")
                                .status(OK)
                                .statusCode(OK.value())
                                .build());
    }

    @GetMapping("/invoice/list")
    public ResponseEntity<HttpResponse> getInvoices (@AuthenticationPrincipal UserDTO user,
                                                      @RequestParam Optional<Integer> page,
                                                      @RequestParam Optional<Integer> size) {
        return ResponseEntity.ok(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .data(of(
                                "user", userService.getUserByEmail(user.getEmail()),
                                "invoices", customerService.getInvoices(page.orElse(0), size.orElse(10))))
                        .message("Invoice retrieved")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    @GetMapping("/invoice/get/{id}")
    public ResponseEntity<HttpResponse> getInvoice (@AuthenticationPrincipal UserDTO user,
                                                    @PathVariable ("id") Long id) {
        return ResponseEntity.ok(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .data(of(
                                "user", userService.getUserByEmail(user.getEmail()),
                                "invoice", customerService.getInvoice(id)))
                        .message("Invoice retrieved")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    @PostMapping("/invoice/add-to-customer/{id}")
    public ResponseEntity<HttpResponse> addInvoiceToCustomer (@AuthenticationPrincipal UserDTO user,
                                                              @PathVariable ("id") Long id,
                                                              @RequestBody Invoice invoice) {
        customerService.addInvoiceToCustomer(id, invoice);
        return ResponseEntity.ok(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .data(of(
                                "user", userService.getUserByEmail(user.getEmail()),
                                "customers", customerService.getCustomers()))
                        .message("Customers retrieved")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }
}
