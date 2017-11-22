'use strict';

describe('Service: profileService', function () {

  // load the service's module
  beforeEach(module('gaHsTestApp'));

  // instantiate service
  var profileService;
  beforeEach(inject(function (_profileService_) {
    profileService = _profileService_;
  }));

  it('should do something', function () {
    expect(!!profileService).toBe(true);
  });

});
