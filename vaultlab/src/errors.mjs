export class VaultLabError extends Error {
  constructor(code, message = "VaultLab operation rejected") {
    super(message);
    this.name = "VaultLabError";
    this.code = code;
  }
}

export function publicError(error) {
  if (error instanceof VaultLabError) {
    return { code: error.code, message: error.message };
  }

  return {
    code: "VAULTLAB_OPERATION_FAILED",
    message: "VaultLab operation failed closed"
  };
}
