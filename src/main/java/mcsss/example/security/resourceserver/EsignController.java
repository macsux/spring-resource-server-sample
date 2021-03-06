package mcsss.example.security.resourceserver;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class EsignController {

    @PostMapping(value = "/complete_signing")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('SCOPE_esignature.complete_signing')")
    public EsignConfirmation callback(@RequestParam String app, @RequestParam String docId) {
        return new EsignConfirmation(app, docId);
    }
}
