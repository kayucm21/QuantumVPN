import unittest
from unittest.mock import patch
try:
    import quantumvpn_four_catalog as four
except ImportError:
    from tools import quantumvpn_four_catalog as four


class FourCatalogTests(unittest.TestCase):
    def test_exact_approved_hundred_without_false_completion(self):
        rows = four.catalog(limit=50)['items'] + four.catalog(offset=50, limit=50)['items']
        self.assertEqual([row['id'] for row in rows], list(range(1, 101)))
        self.assertEqual(len({row['title'] for row in rows}), 100)
        self.assertEqual(four.catalog()['total'], 100)
        self.assertEqual(four.catalog()['scope'], 'roadmap_not_release_completion')
        self.assertEqual(sum(four.catalog()['counts'].values()), 100)

    def test_all_groups_have_ten_distinct_features(self):
        for key, _ in four.GROUPS:
            result = four.catalog(group=key)
            self.assertEqual(result['matched'], 10)
            self.assertIsNone(result['next_offset'])
            self.assertTrue(all(row['group'] == key for row in result['items']))

    def test_search_and_pagination_are_read_only_and_bounded(self):
        self.assertEqual([row['id'] for row in four.catalog(query='pAsSkEy')['items']], [61])
        self.assertEqual(four.catalog(offset=100)['items'], [])
        self.assertEqual(four.catalog(query='<script>')['items'], [])
        self.assertEqual(four.catalog()['next_offset'], 20)

    def test_malformed_inputs_do_not_expand_scope(self):
        for kwargs in ({'query': 'x'*129}, {'query': None}, {'group': '../system'},
                       {'offset': -1}, {'offset': True}, {'limit': 100}, {'limit': 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                four.catalog(**kwargs)

    def test_partial_is_never_counted_as_verified(self):
        with patch.object(four, 'PROGRESS', {25: {'status': 'partial', 'note': 'Physical-device verification pending'}}):
            result = four.catalog(query='25')
            self.assertEqual(result['counts']['verified'], 0)
            self.assertEqual(result['counts']['partial'], 1)


if __name__ == '__main__':
    unittest.main()
