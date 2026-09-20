package it.comune.trieste.ouf.authorization;

import java.security.Principal;
import java.util.Objects;

/** Construct only after token/container authentication and issuer/audience validation.
 * This type is a server SPI, never deserialized from headers or request bodies. */
public record TrustedPrincipal(PrincipalContext context) implements Principal {
  public TrustedPrincipal { Objects.requireNonNull(context); }
  @Override public String getName() { return context.subjectId(); }
}
