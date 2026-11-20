// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import { describe, expect, it } from 'vitest';
import { errorMessage } from './api';

describe('errorMessage', () => {
  it('unwraps the controller {"error": …} envelope', () => {
    expect(errorMessage('{"error":"Get \\"https://k8s/api/v1/pods\\": no such host"}')).toBe('Get "https://k8s/api/v1/pods": no such host');
  });
  it('accepts a {"message": …} envelope', () => {
    expect(errorMessage('{"message":"nope"}')).toBe('nope');
  });
  it('leaves plain text and non-envelope JSON alone', () => {
    expect(errorMessage('Agent reports unavailable')).toBe('Agent reports unavailable');
    expect(errorMessage('{"code":7}')).toBe('{"code":7}');
    expect(errorMessage('{not json')).toBe('{not json');
  });
});
