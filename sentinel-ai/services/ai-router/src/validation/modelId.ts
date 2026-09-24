const MODEL_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/;

/** Model ids are interpolated into request URLs, so they are strictly allow-listed (no slashes or query characters). */
export function assertValidModelId(model: string): string {
  if (!MODEL_ID.test(model) || model.includes("..")) throw new RangeError("invalid model id");
  return model;
}
