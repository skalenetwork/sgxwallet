import plyvel
import sys

def merge_databases(source_db_paths, target_db_path):
    try:
        target_db = plyvel.DB(target_db_path, create_if_missing=True)

        with target_db.write_batch() as batch:
            for source_db_path in source_db_paths:
                source_db = plyvel.DB(source_db_path, create_if_missing=False)
                for key, value in source_db:
                    batch.put(key, value)
                source_db.close()

        print("Merge successful!")

    except Exception as e:
        print("Error:", e)

    finally:
        if target_db:
            target_db.close()

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python merge_leveldb.py source_db_path1 source_db_path2 ... target_db_path")
        sys.exit(1)

    source_db_paths = sys.argv[1:-1]
    target_db_path = sys.argv[-1]

    merge_databases(source_db_paths, target_db_path)
