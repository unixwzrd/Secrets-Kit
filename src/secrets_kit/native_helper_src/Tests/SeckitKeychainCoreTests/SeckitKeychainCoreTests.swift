import XCTest
@testable import SeckitKeychainCore

final class SeckitKeychainCoreTests: XCTestCase {
    func testServiceNameUsesServiceAndName() {
        XCTAssertEqual(
            KeychainHelper.serviceName(service: "sync-test", name: "SECKIT_TEST_ALPHA"),
            "sync-test:SECKIT_TEST_ALPHA"
        )
    }

    func testBaseQueryIncludesSynchronizableForIcloud() {
        let request = HelperRequest(
            command: .exists,
            backend: .icloud,
            service: "sync-test",
            account: "local",
            name: "SECKIT_TEST_ALPHA",
            value: nil,
            label: nil,
            comment: nil
        )
        let query = KeychainHelper.baseQuery(for: request)
        XCTAssertNotNil(query[kSecAttrSynchronizable])
    }
}
